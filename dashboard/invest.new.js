  SCREENS.investigation = {
    title: 'Investigation',
    build: function (root) {
      var H = D.HOSTS.find(function (x) { return x.id === S.host; }) || D.HOSTS[0];
      var hot = H.risk >= 0.65;

      /* ---- headline: selected asset + risk ---- */
      var head = div('greet');
      head.innerHTML =
        '<div><div class="g-k">Investigation · selected asset</div>' +
        '<h1 class="g-t">' + esc(H.id) + ' <span class="ip mono-ip">' + esc(H.ip) + '</span></h1>' +
        '<div class="g-sub">' + esc(H.zone) + ' · ' + esc(H.tech) + ' · ' + H.flows + ' active flows</div></div>' +
        '<div class="g-date"><div class="k">Observed Risk</div><div class="v" style="font-size:26px;color:' + FS.riskColor(H.risk) + '">' + fmt(H.risk) + '</div></div>';
      root.appendChild(head);

      var topGrid = div('grid2-1');

      /* left: attack path (primary) */
      var apPanel = div('panel');
      apPanel.style.marginBottom = '12px';
      var aph = div('panel-hd');
      aph.innerHTML = '<div class="t">Attack Path<span class="sub">&nbsp;·&nbsp; campaign #1 · ' + (hot ? 'active' : 'no active path') + '</span></div><div class="right">' + pill(hot ? 'CRITICAL' : 'NOMINAL', hot ? 'red' : 'green') + '</div>';
      apPanel.appendChild(aph);
      var ap = div('apath');
      if (hot) {
        ap.innerHTML =
          '<div class="node hot"><div class="lbl red">EXTERNAL</div><div class="nm">ext-src</div><div class="ip">192.168.100.7</div><div class="x">risk 0.902</div></div>' +
          '<div class="link dash hot"></div><span class="xmeta">T1110 brute force</span><div class="link dash hot"></div>' +
          '<div class="node hot"><div class="lbl red">DMZ</div><div class="nm">dmz-web</div><div class="ip">10.0.3.10</div><div class="x">risk 0.839</div></div>' +
          '<div class="link dash warm"></div><span class="xmeta">T1021 lateral · 54.4 KB</span><div class="link dash warm"></div>' +
          '<div class="node warm"><div class="lbl amber">SERVERS</div><div class="nm">srv-app</div><div class="ip">10.0.2.40</div><div class="x">risk 0.611</div></div>';
      } else {
        ap.innerHTML =
          '<div class="node cool"><div class="lbl">' + esc(H.zone).toUpperCase() + '</div><div class="nm">' + esc(H.id) + '</div><div class="ip">' + esc(H.ip) + '</div><div class="x">risk ' + fmt(H.risk, 2) + '</div></div>' +
          '<div class="link dash"></div><span class="xmeta">no adversarial path observed</span><div class="link dash"></div>' +
          '<div class="node"><div class="lbl">STATUS</div><div class="nm">' + FS.riskState(H.risk) + '</div><div class="ip">monitoring</div><div class="x">lead ' + D.OVERVIEW.earlyWarning + ' s</div></div>';
      }
      apPanel.appendChild(ap);
      var footTabs = div('tabs');
      footTabs.innerHTML = '<div class="tab active">FLOW EVIDENCE · ' + H.flows + '</div><div class="tab">ATT&CK · ' + esc(H.tech) + '</div>';
      apPanel.appendChild(footTabs);

      /* trajectory chart */
      var trajPanel = panel('Risk Trajectory', '90 windows · host-scaled', null, [
        Object.assign(document.createElement('span'), { className: 'legend', innerHTML: '<span class="li"><span class="sw" style="background:#D6DAD2"></span>OBSERVED</span><span class="li"><span class="sw dash"></span>FORECAST</span><span class="li"><span class="sw fill"></span>95% CONFORMAL</span>' })
      ], { pad: false });
      var kpis = div('inv-kpis');
      var scale = H.risk / 0.95;
      [
        { k: 'Observed', v: fmt(H.risk), cls: H.risk >= 0.65 ? 'red' : H.risk >= 0.45 ? 'amber' : 'green' },
        { k: 'Forecast Peak', v: fmt(Math.min(0.98, H.risk * 1.14)), s: 'at +16s' },
        { k: 'Band at Horizon', v: '±' + fmt(0.12 + scale * 0.05, 3), s: 'at +16s' },
        { k: 'Hazard Onset', v: hot ? '+3s' : 'none', s: hot ? 'within horizon' : 'within horizon' }
      ].forEach(function (c) {
        kpis.innerHTML += '<div class="cell"><div class="k">' + c.k + '</div><div class="v ' + (c.cls || '') + '">' + c.v + '</div><div class="s">' + (c.s || '') + '</div></div>';
      });
      var wrapInv = div();
      wrapInv.appendChild(kpis);
      var chWrap = div('panel-bd');
      var obs = D.windows.map(function (w) { return Math.min(0.98, w.risk * scale * (0.92 + 0.08 * Math.sin(w.i * 0.7))); });
      var fore = [], band = [];
      var target = Math.min(0.98, H.risk * 1.14);
      for (var i = 0; i < 8; i++) {
        var v = H.risk + (target - H.risk) * Math.pow((i + 1) / 8, 1.2);
        fore.push(Math.max(0.02, v)); band.push([Math.max(0.01, v - 0.1 - i * 0.012), Math.min(1, v + 0.07 + i * 0.015)]);
      }
      chWrap.appendChild(FS.seriesChart({
        w: 760, h: 230, obs: obs, fore: fore, band: band, foreAppend: 8, threshold: 0.65,
        xLabels: [{ i: 0, t: '19:43:19' }, { i: 44, t: '19:44:23' }, { i: 89, t: 'NOW' }, { i: 97, t: '+16s', anchor: 'end' }]
      }));
      var bandNote = div('hint');
      bandNote.innerHTML = 'BAND · Branch B conformal radii · α = 0.05 · finite-sample &nbsp;&nbsp;&nbsp; window Δt 2.0s · horizon 16s';
      wrapInv.appendChild(chWrap);
      wrapInv.appendChild(div('scanline'));
      wrapInv.appendChild(bandNote);
      trajPanel.appendChild(wrapInv);

      var leftCol = div();
      leftCol.appendChild(apPanel);
      leftCol.appendChild(trajPanel);
      topGrid.appendChild(leftCol);

      /* right: attribution + host state + state vector */
      var rightCol = div();

      /* attribution — input × gradient over real features */
      var at = div('panel');
      at.style.marginBottom = '12px';
      var ath = div('panel-hd');
      ath.innerHTML = '<div class="t">Model Attribution<span class="sub">&nbsp;·&nbsp; input × gradient</span></div>';
      at.appendChild(ath);
      var atb = div('panel-bd');
      var baseAttrs = [['syn_rate', 12.9], ['avg_duration', 9.8], ['H_emb_0', 9.5], ['H_emb_4', 9.6], ['fwd_bytes', 7.2], ['unique_peers', 6.4]];
      baseAttrs.forEach(function (a) {
        var row = div('attr-row');
        row.innerHTML = '<span class="nm' + (a[1] > 9 ? ' hot' : '') + '">' + a[0] + '</span>' +
          '<span class="bar"><i style="width:' + a[1] * 6 + '%"></i></span>' +
          '<span class="pc">' + a[1].toFixed(1) + '%</span>';
        atb.appendChild(row);
      });
      atb.appendChild(div('hint', 'Feature contributions to the current risk score — 66-feature behavioral space.'));
      at.appendChild(atb);
      rightCol.appendChild(at);

      /* host state */
      var hs = div('panel');
      hs.style.marginBottom = '12px';
      var hsh = div('panel-hd');
      hsh.innerHTML = '<div class="t">Host State</div>';
      hs.appendChild(hsh);
      var hsb = div('panel-bd');
      [['Address', H.ip], ['Zone', H.zone.toUpperCase()], ['Active flows', String(H.flows)],
       ['Technique', H.tech], ['Risk state', FS.riskState(H.risk)]].forEach(function (kv) {
        var row = div('mv-row');
        row.innerHTML = '<span class="k">' + kv[0] + '</span><span class="v' + (kv[0] === 'Risk state' ? '" style="color:' + FS.riskColor(H.risk) : '') + '">' + esc(kv[1]) + '</span>';
        hsb.appendChild(row);
      });
      hs.appendChild(hsb);
      rightCol.appendChild(hs);

      /* state vector */
      var sv = div('panel');
      sv.style.marginBottom = '0';
      var svhd = div('panel-hd');
      svhd.innerHTML = '<div class="t">State Vector <b>27→0</b></div><div class="right">' + pill('INDEX', 'lite') + pill('WEIGHT', 'lite') + '</div>';
      sv.appendChild(svhd);
      var svbd = div('panel-bd sv-list');
      svbd.style.maxHeight = '420px';
      var grp1 = div('smallcaps'); grp1.style.padding = '2px 0 6px'; grp1.textContent = 'TONE LATENT · H_EMB 0–11';
      svbd.appendChild(grp1);
      D.STATE_VECTOR.forEach(function (r, ix) {
        if (ix === 12) {
          var grp2 = div('smallcaps'); grp2.style.cssText = 'padding:8px 0 6px';
          grp2.textContent = 'HOST ATTRIBUTES · CLIPPED [0,1]';
          svbd.appendChild(grp2);
        }
        var row = div('sv-row');
        row.innerHTML = '<span class="ix">' + pad(ix) + '</span>' +
          '<span class="nm' + (r.hot ? ' hot' : '') + '">' + esc(r.nm) + '</span>' +
          '<span class="w">' + (r.hot ? '+' : '−') + Math.abs(r.v).toFixed(3).slice(1) + '</span>' +
          '<span class="bar"><i style="width:' + Math.round(r.v * 100) + '%" class="' + (r.hot ? '' : 'neg') + '"></i></span>' +
          '<span class="val">' + (2 + (ix % 5)) + '.' + (ix % 9) + '</span>';
        row.title = r.nm + ' = ' + r.v;
        svbd.appendChild(row);
      });
      sv.appendChild(svbd);
      rightCol.appendChild(sv);
      topGrid.appendChild(rightCol);
      root.appendChild(topGrid);

      function pad(n) { return (n < 10 ? '0' : '') + n; }
    }
  };
