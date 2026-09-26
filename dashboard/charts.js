/* ============================================================
   FluxShield — SVG helpers + chart renderers (flat, thin, dark)
   ============================================================ */
window.FS = (function () {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';
  var LIVE = [];
  function registerLive(svg){ if (LIVE.indexOf(svg)<0) LIVE.push(svg); }
  var MONO = "'IBM Plex Mono', monospace";
  function el(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function div(cls, html) {
    var d = document.createElement('div');
    if (cls) d.className = cls;
    if (html != null) d.innerHTML = html;
    return d;
  }
  function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function fmt(n, d) { return Number(n).toFixed(d == null ? 3 : d); }
  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  function secOfDay(s) { return pad2(Math.floor(s / 3600) % 24) + ':' + pad2(Math.floor(s / 60) % 60) + ':' + pad2(s % 60); }

  /* risk color ladder (flat) */
  function riskColor(r) {
    if (r >= 0.65) return '#E15252';
    if (r >= 0.45) return '#E0A84A';
    if (r >= 0.20) return '#A8ADA5';
    return '#A8D93F';
  }
  function riskState(r) {
    if (r >= 0.65) return 'HIGH';
    if (r >= 0.45) return 'ELEV';
    if (r >= 0.20) return 'GUARDED';
    return 'NOMINAL';
  }

  /* ---------- line/area series chart ---------- */
  /* cfg: {w,h,obs:[],fore:[],peak:[],band:[],threshold,xLabels:[],nowIndex,yMax, colors:{}} */
  function seriesChart(cfg) {
    var w = cfg.w || 640, h = cfg.h || 190;
    var mL = 34, mR = 10, mT = 10, mB = cfg.xLabels ? 20 : 8;
    var iw = w - mL - mR, ih = h - mT - mB;
    var svg = el('svg', { viewBox: '0 0 ' + w + ' ' + h, preserveAspectRatio: 'none' });
    svg.classList.add('chart');
    var yMax = cfg.yMax || 1;
    var n = (cfg.obs ? cfg.obs.length : 0);
    if (!n) return svg;
    var total = cfg.foreAppend ? n + cfg.foreAppend : n;
    function X(i) { return mL + (i / (total - 1)) * iw; }
    function Y(v) { return mT + (1 - v / yMax) * ih; }

    /* teal live dot that rides the observed trace */
    if (cfg.live !== false) {
      var dot = el('circle', { r: 2.6, fill: '#C9FF3F', opacity: '0.9' }, svg);
      registerLive({ svg: svg, dot: dot, cfg: cfg, X: X, Y: Y, mL: mL });
    }

    /* y grid */
    var steps = [0, 0.25, 0.5, 0.75, 1];
    steps.forEach(function (v) {
      var y = Y(v * yMax);
      el('line', { x1: mL, x2: w - mR, y1: y, y2: y, stroke: v === 0 ? '#222522' : 'rgba(244,245,241,.05)', 'stroke-width': 1 }, svg);
      var t = el('text', { x: mL - 5, y: y + 3, 'text-anchor': 'end', 'font-size': 8, fill: '#565B54', 'font-family': MONO }, svg);
      t.textContent = String(v);
    });

    /* threshold */
    if (cfg.threshold != null) {
      var ty = Y(cfg.threshold);
      el('line', { x1: mL, x2: w - mR, y1: ty, y2: ty, stroke: '#E15252', 'stroke-width': 1, 'stroke-dasharray': '3 3', opacity: .8 }, svg);
      var tt = el('text', { x: mL + 4, y: ty - 3, 'font-size': 8, fill: '#737871', 'font-family': MONO }, svg);
      tt.textContent = 'THRESHOLD ' + fmt(cfg.threshold, 2);
    }

    /* forecast band */
    if (cfg.band && cfg.foreAppend) {
      var pts = '';
      for (var i = 0; i < cfg.foreAppend; i++) {
        var bi = n + i;
        if (bi === n) pts = 'M' + X(bi) + ',' + Y(cfg.band[i][0]);
        else pts += ' L' + X(bi) + ',' + Y(cfg.band[i][0]);
      }
      for (var j = cfg.foreAppend - 1; j >= 0; j--) {
        pts += ' L' + X(n + j) + ',' + Y(cfg.band[j][1]);
      }
      el('path', { d: pts, fill: 'rgba(201,255,63,.09)', stroke: 'none', opacity: .95 }, svg);
    }

    /* observed area + line (sand) */
    function pathOf(arr, from) {
      var d = '';
      for (var i = from || 0; i < arr.length; i++) d += (i === (from || 0) ? 'M' : 'L') + X(i) + ',' + Y(arr[i]);
      return d;
    }
    if (cfg.area !== false) {
      var area = pathOf(cfg.obs) + ' L' + X(n - 1) + ',' + Y(0) + ' L' + X(0) + ',' + Y(0) + ' Z';
      el('path', { d: area, fill: 'rgba(201,255,63,.07)', opacity: 1, stroke: 'none' }, svg);
    }
    el('path', { d: pathOf(cfg.obs), fill: 'none', stroke: cfg.cObs || '#D6DAD2', 'stroke-width': 1.4 }, svg);

    /* forecast peak (dashed) — teal */
    if (cfg.peak) {
      var pk = cfg.obs.concat(cfg.peak);
      var d2 = '';
      for (var k = 0; k < pk.length; k++) {
        if (k < n - 1 && !cfg.foreFrom) continue;
        d2 += (d2 === '' ? 'M' : 'L') + X(k) + ',' + Y(pk[k]);
      }
      if (cfg.foreFrom != null) {
        d2 = '';
        for (var m = cfg.foreFrom; m < pk.length; m++) d2 += (d2 === '' ? 'M' : 'L') + X(m) + ',' + Y(pk[m]);
      }
      el('path', { d: d2, fill: 'none', stroke: '#C9FF3F', 'stroke-width': 1, 'stroke-dasharray': '4 3', opacity: .8 }, svg);
    }
    if (cfg.fore) {
      var d3 = '';
      for (var f = 0; f < cfg.fore.length; f++) d3 += (f === 0 ? 'M' : 'L') + X(n - 1 + f) + ',' + Y(cfg.fore[f]);
      /* connect */
      el('path', { d: 'M' + X(n - 1) + ',' + Y(cfg.obs[n - 1]) + ' ' + d3.replace('M', 'L'), fill: 'none', stroke: cfg.cFore || '#C9FF3F', 'stroke-width': 1, 'stroke-dasharray': '2 3' }, svg);
    }

    /* NOW divider */
    if (cfg.nowIndex != null) {
      el('line', { x1: X(cfg.nowIndex), x2: X(cfg.nowIndex), y1: mT, y2: mT + ih, stroke: '#F4F5F1', 'stroke-width': 1, opacity: .7 }, svg);
    }
    /* vertical gridlines */
    if (cfg.vgrid) {
      for (var g = 0; g < cfg.vgrid.length; g++) {
        var gi = cfg.vgrid[g];
        el('line', { x1: X(gi), x2: X(gi), y1: mT, y2: mT + ih, stroke: '#0A0C0A', 'stroke-width': 1 }, svg);
      }
    }

    /* x labels */
    if (cfg.xLabels) {
      cfg.xLabels.forEach(function (lb) {
        var t = el('text', { x: X(lb.i), y: h - 5, 'text-anchor': lb.anchor || 'middle', 'font-size': 8, fill: '#565B54', 'font-family': MONO }, svg);
        t.textContent = lb.t;
      });
    }

    /* hover crosshair: vertical line + value flag, follows mouse */
    if (cfg.hover !== false && cfg.obs) {
      var xh = el('line', { y1: mT, y2: mT + ih, stroke: 'rgba(244,245,241,.28)', 'stroke-width': 1, visibility: 'hidden' }, svg);
      var xhc = el('circle', { r: 3, fill: '#D7FF63', stroke: '#050706', 'stroke-width': 1, visibility: 'hidden' }, svg);
      var xht = el('text', { 'font-size': 8.5, fill: '#F4F5F1', 'font-family': MONO, visibility: 'hidden' }, svg);
      var xhb = el('rect', { height: 14, fill: '#111312', stroke: '#292C29', visibility: 'hidden' }, svg);
      var bandRect = el('rect', { x: mL, y: mT, width: iw, height: ih, fill: 'transparent' }, svg);
      svg.insertBefore(bandRect, svg.firstChild.nextSibling || svg.firstChild);
      function onMove(ev) {
        var r = svg.getBoundingClientRect();
        var fx = (ev.clientX - r.left) / r.width * w;
        if (fx < mL || fx > w - mR) { return; }
        var fi = (fx - mL) / iw * (total - 1);
        var i0 = Math.max(0, Math.min(n - 1, Math.floor(fi)));
        var v = cfg.obs[i0];
        if (v == null) return;
        var px = X(i0), py = Y(v);
        xh.setAttribute('x1', px); xh.setAttribute('x2', px); xh.setAttribute('visibility', 'visible');
        xhc.setAttribute('cx', px); xhc.setAttribute('cy', py); xhc.setAttribute('visibility', 'visible');
        var lblStr = (cfg.xLabels && cfg.xLabels.length) ? (cfg.xLabels.reduce(function (a, b) { return Math.abs(b.i - i0) < Math.abs(a.i - i0) ? b : a; }).t) : ('w' + (i0 + 1));
        var txt = lblStr + '  ·  ' + fmt(v, 3);
        xht.textContent = txt; xht.setAttribute('visibility', 'visible');
        var tw2 = txt.length * 5.2 + 10;
        var tx = Math.min(w - mR - tw2, Math.max(mL, px + 6));
        xhb.setAttribute('x', tx); xhb.setAttribute('y', mT + 2); xhb.setAttribute('width', tw2); xhb.setAttribute('visibility', 'visible');
        xht.setAttribute('x', tx + 5); xht.setAttribute('y', mT + 12);
      }
      function onLeave() {
        [xh, xhc, xht, xhb].forEach(function (e2) { e2.setAttribute('visibility', 'hidden'); });
      }
      bandRect.addEventListener('mousemove', onMove);
      bandRect.addEventListener('mouseleave', onLeave);
    }
    return svg;
  }

  /* ---------- mini lattice (hatched future bars) ---------- */
  function lattice(n, hotIdx) {
    var g = div('rp-lattice');
    for (var i = 0; i < n; i++) {
      var b = document.createElement('i');
      if (hotIdx && hotIdx.indexOf(i) >= 0) b.style.borderColor = '#E15252';
      g.appendChild(b);
    }
    return g;
  }

  /* ---------- live tick: ride dots + risk sweep ---------- */
  setInterval(function () {
    if (document.hidden) return;
    var now = performance.now() / 1000;
    LIVE = LIVE.filter(function (L) { return L.svg.isConnected; });
    LIVE.forEach(function (L) {
      var n = L.cfg.obs.length;
      var total = L.cfg.foreAppend ? n + L.cfg.foreAppend : n;
      var phase = (now * 0.14) % 1;
      var fi = phase * (total - 1);
      var i0 = Math.min(n - 1, Math.floor(fi));
      var fr = fi - i0;
      var arr = L.cfg.obs;
      var v = i0 < n - 1 ? (arr[i0] + (arr[i0 + 1] - arr[i0]) * fr) : arr[n - 1];
      var x = L.mL + (fi / (total - 1)) * (L.svg.viewBox.baseVal.width - L.mL - 10);
      var y = L.Y(v);
      L.dot.setAttribute('cx', x);
      L.dot.setAttribute('cy', y);
      var pulse = 0.55 + 0.45 * Math.sin(now * 2.4);
      L.dot.setAttribute('opacity', (0.35 + pulse * 0.55).toFixed(2));
    });
  }, 90);

  return {
    el: el, div: div, esc: esc, fmt: fmt, secOfDay: secOfDay,
    riskColor: riskColor, riskState: riskState,
    seriesChart: seriesChart, lattice: lattice
  };
})();
