/* ============================================================
   FluxShield — pipeline data loader (contract v1)
   Fetches data.json written by the ML pipeline, validates each
   section, and merges over built-in fixtures. Any bad/missing
   section falls back individually — the UI never breaks.
   Provenance is exposed as window.FSDATA.provenance
   { live:bool, source:string, generatedAt:string, errors:[] }.
   ============================================================ */
window.FSLOAD = (function () {
  'use strict';

  function isNum(v) { return typeof v === 'number' && isFinite(v); }
  function clamp01(v) { return Math.max(0, Math.min(1, v)); }
  function isStr(v) { return typeof v === 'string' && v.length > 0; }
  function isArr(v) { return Object.prototype.toString.call(v) === '[object Array]'; }
  function isObj(v) { return v && typeof v === 'object' && !isArr(v); }

  var errors = [];

  function warn(msg) { errors.push(msg); }

  /* ---------- section validators: return cleaned value or null ---------- */

  function vOverview(d) {
    if (!isObj(d)) return null;
    var o = {};
    if (isNum(d.observedRisk)) o.observedRisk = clamp01(d.observedRisk);
    if (isNum(d.maxFuture)) o.maxFuture = clamp01(d.maxFuture);
    if (isNum(d.earlyWarning) && d.earlyWarning >= 0) o.earlyWarning = d.earlyWarning;
    if (isStr(d.source)) o.source = d.source;
    if (isNum(d.anomaly)) o.anomaly = d.anomaly;
    if (isNum(d.throughput)) o.throughput = d.throughput;
    if (isStr(d.flows)) o.flows = d.flows;
    if (isStr(d.packets)) o.packets = d.packets;
    if (isStr(d.pipeline)) o.pipeline = d.pipeline;
    if (isNum(d.loss)) o.loss = d.loss;
    if (isNum(d.windowsRetained)) o.windows = d.windowsRetained;
    if (isObj(d.predicted)) {
      var p = {};
      if (isStr(d.predicted.tid)) p.tid = d.predicted.tid;
      if (isStr(d.predicted.name)) p.name = d.predicted.name;
      if (isStr(d.predicted.tactic)) p.tactic = d.predicted.tactic;
      if (isNum(d.predicted.conf)) p.conf = clamp01(d.predicted.conf);
      if (isStr(d.predicted.desc)) p.desc = d.predicted.desc;
      if (Object.keys(p).length) o.predicted = p;
    }
    return Object.keys(o).length ? o : null;
  }

  function vML(d) {
    if (!isObj(d)) return null;
    var m = {};
    if (isStr(d.model)) m.model = d.model;
    if (isStr(d.calibration)) m.calibration = d.calibration;
    if (isNum(d.threshold) && d.threshold > 0 && d.threshold < 1) m.threshold = d.threshold;
    if (isNum(d.features) && d.features > 0) m.features = d.features;
    if (isStr(d.evalProtocol)) m.evalProtocol = d.evalProtocol;
    if (isNum(d.trackB) && d.trackB > 0 && d.trackB <= 100) m.trackB = d.trackB;
    if (isArr(d.early)) {
      var early = [];
      d.early.forEach(function (e) {
        if (isObj(e) && isStr(e.t) && isNum(e.recall) && e.recall > 0 && e.recall <= 100) {
          early.push({ t: e.t, recall: e.recall });
        }
      });
      if (early.length) m.early = early;
    }
    if (isArr(d.final)) {
      var fin = [];
      d.final.forEach(function (e) {
        if (isObj(e) && isStr(e.k) && isStr(e.v)) fin.push({ k: e.k, v: e.v });
      });
      if (fin.length) m.final = fin;
    }
    if (isArr(d.comparison)) {
      var cmp = [];
      d.comparison.forEach(function (e) {
        if (isObj(e) && isStr(e.nm) && isNum(e.f1) && e.f1 > 0 && e.f1 <= 100) {
          cmp.push({ nm: e.nm, f1: e.f1, sel: !!e.sel, why: isStr(e.why) ? e.why : '' });
        }
      });
      if (cmp.length) m.comparison = cmp;
    }
    return Object.keys(m).length ? m : null;
  }

  function vWindows(d) {
    if (!isArr(d) || !d.length) return null;
    var out = [];
    for (var i = 0; i < d.length; i++) {
      var w = d[i];
      if (!isObj(w) || !isNum(w.risk)) { warn('windows[' + i + '] skipped (no risk)'); continue; }
      var risk = clamp01(w.risk);
      out.push({
        i: isNum(w.i) ? w.i : out.length,
        risk: risk,
        peak: isNum(w.peak) ? clamp01(w.peak) : Math.min(0.98, risk + 0.12),
        pps: isNum(w.pps) && w.pps >= 0 ? w.pps : Math.round(900 + risk * 5200),
        flow: isNum(w.flow) && w.flow >= 0 ? w.flow : Math.round(30 + risk * 90),
        alert: typeof w.alert === 'boolean' ? w.alert : risk >= 0.65,
        stage: isStr(w.stage) ? w.stage : '—',
        technique: isStr(w.technique) ? w.technique : '—',
        target: isStr(w.target) ? w.target : '—',
        tsec: isNum(w.tsec) && w.tsec >= 0 ? w.tsec : out.length * 2
      });
    }
    return out.length ? out : null;
  }

  function vHosts(d) {
    if (!isArr(d) || !d.length) return null;
    var out = [];
    d.forEach(function (h, i) {
      if (!isObj(h) || !isStr(h.id) || !isNum(h.risk)) { warn('hosts[' + i + '] skipped'); return; }
      var state = h.state === 'high' || h.state === 'susp' || h.state === 'norm' ? h.state
        : (h.risk >= 0.65 ? 'high' : h.risk >= 0.45 ? 'susp' : 'norm');
      out.push({
        id: h.id,
        ip: isStr(h.ip) ? h.ip : '—',
        zone: isStr(h.zone) ? h.zone : '—',
        kind: isStr(h.kind) ? h.kind : 'server',
        risk: clamp01(h.risk),
        state: state,
        tech: isStr(h.tech) ? h.tech : '—',
        flows: isNum(h.flows) && h.flows >= 0 ? h.flows : 0
      });
    });
    return out.length ? out : null;
  }

  function vBranches(d) {
    if (!isArr(d) || !d.length) return null;
    var out = [];
    d.forEach(function (b, i) {
      if (!isObj(b) || !isStr(b.id) || !isNum(b.p)) { warn('branches[' + i + '] skipped'); return; }
      out.push({
        id: b.id,
        p: Math.max(0, Math.min(100, b.p)),
        tid: isStr(b.tid) ? b.tid : '—',
        desc: isStr(b.desc) ? b.desc : '—',
        ttE: isStr(b.ttE) ? b.ttE : '—',
        asset: isStr(b.asset) ? b.asset : '—',
        risk: isNum(b.risk) ? clamp01(b.risk) : 0,
        color: b.color === 'red' || b.color === 'amber' || b.color === 'dim' ? b.color : 'dim'
      });
    });
    return out.length ? out : null;
  }

  function vIncidents(d) {
    if (!isArr(d) || !d.length) return null;
    var out = [];
    d.forEach(function (n, i) {
      if (!isObj(n) || !isStr(n.id)) { warn('incidents[' + i + '] skipped'); return; }
      out.push({
        id: n.id,
        sev: isStr(n.sev) ? n.sev : 'MED',
        status: n.status === 'TRIAGING' || n.status === 'CONTAINED' || n.status === 'CLOSED' ? n.status : 'TRIAGING',
        tid: isStr(n.tid) ? n.tid : '—',
        tech: isStr(n.tech) ? n.tech : '—',
        target: isStr(n.target) ? n.target : '—',
        ip: isStr(n.ip) ? n.ip : '—',
        peak: isNum(n.peak) ? clamp01(n.peak) : 0,
        lead: isNum(n.lead) && n.lead >= 0 ? n.lead : 0,
        dur: isStr(n.dur) ? n.dur : '—',
        analyst: isStr(n.analyst) ? n.analyst : '—',
        alerts: isNum(n.alerts) ? n.alerts : 0,
        opened: isStr(n.opened) ? n.opened : '—',
        evidence: isNum(n.evidence) ? n.evidence : 0
      });
    });
    return out.length ? out : null;
  }

  function vEvents(d) {
    if (!isArr(d) || !d.length) return null;
    var out = [];
    d.forEach(function (e, i) {
      if (!isObj(e) || !isStr(e.msg)) { warn('events[' + i + '] skipped'); return; }
      out.push({
        ts: isStr(e.ts) ? e.ts : '—',
        sev: e.sev === 'CRIT' || e.sev === 'WARN' || e.sev === 'INFO' ? e.sev : 'INFO',
        src: isStr(e.src) ? e.src : 'system',
        host: isStr(e.host) ? e.host : '—',
        msg: e.msg
      });
    });
    return out.length ? out : null;
  }

  function vPredictions(d) {
    if (!isArr(d) || !d.length) return null;
    var out = [];
    d.forEach(function (p, i) {
      if (!isObj(p) || !isStr(p.tid) || !isNum(p.p)) { warn('predictions[' + i + '] skipped'); return; }
      out.push({
        tid: p.tid,
        name: isStr(p.name) ? p.name : p.tid,
        p: clamp01(p.p),
        eta: isStr(p.eta) ? p.eta : '—',
        conf: isStr(p.conf) ? p.conf : (isNum(p.conf) ? String(p.conf) : '—')
      });
    });
    return out.length ? out : null;
  }

  function vStateVector(d) {
    if (!isArr(d) || !d.length) return null;
    var out = [];
    d.forEach(function (r, i) {
      if (!isObj(r) || !isStr(r.nm) || !isNum(r.v)) { warn('stateVector[' + i + '] skipped'); return; }
      out.push({ nm: r.nm, v: clamp01(r.v), hot: !!r.hot });
    });
    return out.length ? out : null;
  }

  function vAttack(d) {
    if (!isArr(d) || !d.length) return null;
    var out = [];
    d.forEach(function (t, i) {
      if (!isObj(t) || !isStr(t.tactic) || !isArr(t.items)) { warn('attack[' + i + '] skipped'); return; }
      var items = [];
      t.items.forEach(function (it) {
        if (isObj(it) && isStr(it.id) && isStr(it.name)) {
          items.push({
            id: it.id, name: it.name,
            state: it.state === 'hot' || it.state === 'warm' ? it.state : '',
            p: isNum(it.p) ? clamp01(it.p) : 0
          });
        }
      });
      if (items.length) out.push({ tactic: t.tactic, items: items });
    });
    return out.length ? out : null;
  }

  function vCampaign(d) {
    if (!isObj(d)) return null;
    var c = {};
    if (isStr(d.id)) c.id = d.id;
    if (isStr(d.started)) c.started = d.started;
    if (isNum(d.hosts)) c.hosts = d.hosts;
    if (isNum(d.flows)) c.flows = d.flows;
    if (isNum(d.alerts)) c.alerts = d.alerts;
    if (isArr(d.stages)) {
      var st = [];
      d.stages.forEach(function (s) {
        if (isObj(s) && isStr(s.nm)) st.push({ nm: s.nm, ts: isStr(s.ts) ? s.ts : '—', done: !!s.done, tid: isStr(s.tid) ? s.tid : '—' });
      });
      if (st.length) c.stages = st;
    }
    return Object.keys(c).length ? c : null;
  }

  /* ---------- merge + boot ---------- */

  function merge(fix, live) {
    /* [FSDATA key, contract key (data.json), validator] */
    var map = [
      ['OVERVIEW',    'overview',    vOverview],
      ['ML',          'ml',          vML],
      ['windows',     'windows',     vWindows],   /* data.js uses lowercase here */
      ['HOSTS',       'hosts',       vHosts],
      ['BRANCHES',    'branches',    vBranches],
      ['INCIDENTS',   'incidents',   vIncidents],
      ['EVENTS',      'events',      vEvents],
      ['PREDICTIONS', 'predictions', vPredictions],
      ['STATE_VECTOR', 'stateVector', vStateVector],
      ['ATTACK',      'attack',      vAttack],
      ['CAMPAIGN',    'campaign',    vCampaign]
    ];
    var out = {};
    /* always seed from the pristine fixture snapshot — never from current
       FSDATA, which live polls may have overwritten (so a later poll can
       still fall back cleanly when a section disappears or turns invalid) */
    var base = fix.FIXTURES || fix;
    map.forEach(function (m) { out[m[0]] = base[m[0]]; });
    var applied = 0;
    map.forEach(function (m) {
      var fkey = m[0], lkey = m[1], validate = m[2];
      if (live && (lkey in live)) {
        var v = validate(live[lkey]);
        if (v != null) { out[fkey] = v; applied++; }
        else warn('section "' + lkey + '" invalid — using fixture');
      }
    });
    return { data: out, applied: applied };
  }

  var booted = false;
  var pollTimer = null;
  var POLL_MS = 30000;
  var lastSnapshot = null;   /* JSON of last applied merged data (change detection) */

  function applyDoc(doc) {
    var F = window.FSDATA;
    if (!isObj(doc)) throw new Error('not an object');
    errors.length = 0; /* per-apply warnings, not cumulative across polls */
    if (isObj(doc.meta) && doc.meta.schema_version !== 1) {
      warn('schema_version ' + doc.meta.schema_version + ' — attempting v1 parse');
    }
    var res = merge(F, doc);
    var snapshot = JSON.stringify(res.data);
    var changed = snapshot !== lastSnapshot;
    /* apply the merged document onto FSDATA in place (app.js holds a
       reference to this object, so reassignment would be invisible) */
    Object.keys(res.data).forEach(function (k) { F[k] = res.data[k]; });
    F.provenance = {
      live: true,
      source: isObj(doc.meta) && isStr(doc.meta.source) ? doc.meta.source : 'pipeline',
      generatedAt: isObj(doc.meta) && isStr(doc.meta.generated_at) ? doc.meta.generated_at : '—',
      sections: res.applied,
      errors: errors
    };
    if (errors.length) console.warn('[FSLOAD] fallbacks applied:', errors.join('; '));
    console.info('[FSLOAD] live data: ' + res.applied + ' sections from ' + F.provenance.source);
    lastSnapshot = snapshot;
    return changed;
  }

  function failToFixtures(e) {
    window.FSDATA.provenance = { live: false, source: 'built-in fixtures', generatedAt: '—', sections: 0, errors: errors };
    console.info('[FSLOAD] no pipeline data (' + e.message + ') — running on fixtures');
  }

  function emitChange(kind) {
    try {
      /* dispatched on document: reaches document listeners (app.js) and
         bubbles to window listeners; a window dispatch would do neither */
      document.dispatchEvent(new CustomEvent('fs:data', {
        detail: { kind: kind, provenance: window.FSDATA.provenance }
      }));
    } catch (e) { /* very old browsers: next poll still updates data */ }
  }

  function fetchDoc(initial) {
    return fetch('data.json', { cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (doc) {
        var changed = applyDoc(doc);
        if (!initial && changed) emitChange('update');
      })
      .catch(function (e) {
        if (!initial && window.FSDATA.provenance && window.FSDATA.provenance.live) {
          /* transient poll failure: keep last good data + provenance */
          console.warn('[FSLOAD] poll failed, keeping last good data (' + e.message + ')');
        } else {
          failToFixtures(e);
        }
      });
  }

  function boot() {
    if (booted) return;
    booted = true;
    fetchDoc(true).finally(function () {
      window.FSBOOT && window.FSBOOT();
      startPolling();
    });
  }

  function tick() {
    if (document.hidden) return; /* skip polls while the tab is hidden */
    fetchDoc(false);
  }

  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(tick, POLL_MS);
    document.addEventListener('visibilitychange', function () {
      /* catch up immediately when the tab becomes visible again */
      if (!document.hidden && booted) fetchDoc(false);
    });
  }

  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  /* auto-boot: loader loads before app.js registers FSBOOT, so defer to
     DOMContentLoaded — by then all four scripts have executed. */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  return { boot: boot, refresh: function () { return fetchDoc(false); }, startPolling: startPolling, stopPolling: stopPolling };
})();
