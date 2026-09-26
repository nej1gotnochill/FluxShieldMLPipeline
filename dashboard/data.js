/* ============================================================
   FluxShield — datasets (static fixture data for the SOC UI)
   ============================================================ */
window.FSDATA = (function () {
  'use strict';

  /* ---------- ML metrics (project numbers) ---------- */
  var ML = {
    model: 'ExtraTrees 300',
    calibration: 'Sigmoid',
    threshold: 0.5,
    features: 66,
    evalProtocol: 'Capture-disjoint · attack-family holdout',
    early: [
      { t: '1 s', recall: 68.16 },
      { t: '3 s', recall: 99.79 },
      { t: '5 s', recall: 99.79 }
    ],
    trackB: 97.40,
    final: [
      { k: 'Recall', v: '99.7849%' },
      { k: 'Precision', v: '99.9998%' },
      { k: 'F1', v: '99.8922%' },
      { k: 'FPR', v: '0.018%' }
    ]
  };

  /* ---------- deterministic RNG ---------- */
  function mulberry32(a) {
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  /* ---------- 90 risk windows (capture timeline) ---------- */
  var rnd = mulberry32(42);
  var N = 90;
  var windows = [];
  var base = 0.30;
  for (var i = 0; i < N; i++) {
    var w = {};
    w.i = i;
    // two elevated phases: 0-14 ramp, 15-38 high, 39-52 decay, 53-64 low, 65-78 second wave, 79-89 settle
    var phase;
    if (i <= 14) phase = base + (i / 14) * 0.42;            // ramp to ~0.72
    else if (i <= 38) phase = 0.72 + rnd() * 0.10;          // high ~0.72-0.82
    else if (i <= 52) phase = 0.72 - ((i - 38) / 14) * 0.55; // decay to ~0.17
    else if (i <= 64) phase = 0.16 + rnd() * 0.05;          // quiet
    else if (i <= 78) phase = 0.30 + ((i - 64) / 14) * 0.38 + rnd() * 0.06; // second wave to ~0.70
    else phase = 0.68 - ((i - 78) / 11) * 0.45 + rnd() * 0.04; // settle to ~0.24
    w.risk = Math.max(0.03, Math.min(0.95, phase));
    w.peak = Math.min(0.98, w.risk + 0.10 + rnd() * 0.12);
    w.pps = Math.round(900 + w.risk * 5200 + rnd() * 700);
    w.flow = Math.round(30 + w.risk * 90 + rnd() * 20);
    w.alert = w.risk >= 0.65;
    w.stage = i < 8 ? 'RECON' : i < 30 ? 'INITIAL ACCESS' : i < 38 ? 'EXECUTION' : i < 44 ? 'C2' : i < 56 ? 'LATERAL' : i < 70 ? 'EXFIL' : 'CLEAR';
    w.technique = i < 8 ? 'T1046' : i < 30 ? 'T1190' : i < 38 ? 'T1059' : i < 44 ? 'T1071' : i < 56 ? 'T1021' : i < 70 ? 'T1041' : '—';
    w.target = i < 30 ? 'dmz-web · 10.0.3.10' : i < 44 ? 'dmz-web' : i < 56 ? 'srv-app' : i < 70 ? 'srv-db' : '—';
    w.tsec = 19 * 3600 + 43 * 60 + 19 + i * 2; // seconds-of-day, 2s windows
    windows.push(w);
  }
  // headline numbers (latest window)
  var last = windows[N - 1];
  var OVERVIEW = {
    observedRisk: 0.739,
    predicted: { tid: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'TA0001 Initial Access', conf: 0.833, desc: 'Exploit attempts against the public-facing application.' },
    maxFuture: 0.953,
    source: 'rule-adjusted · model 0.559',
    earlyWarning: 6.8,
    milestone: 'InitialAccess',
    anomaly: 95.3, throughput: 547.9, flows: '1.5k', packets: '11.2k',
    pipeline: '11.7 ms', loss: 3.03, windows: 90
  };

  /* ---------- hosts ---------- */
  var HOSTS = [
    { id: 'dmz-web',  ip: '10.0.3.10',  zone: 'DMZ',      kind: 'server',       risk: 0.839, state: 'high',  tech: 'T1190 · T1110', flows: 412 },
    { id: 'srv-app',  ip: '10.0.2.40',  zone: 'Servers',  kind: 'server',       risk: 0.611, state: 'susp',  tech: 'T1021',         flows: 188 },
    { id: 'srv-db',   ip: '10.0.2.50',  zone: 'Servers',  kind: 'db',           risk: 0.567, state: 'susp',  tech: 'T1021 · T1041', flows: 96 },
    { id: 'srv-id',   ip: '10.0.2.20',  zone: 'Servers',  kind: 'server',       risk: 0.234, state: 'norm',  tech: '—',             flows: 74 },
    { id: 'srv-file', ip: '10.0.2.30',  zone: 'Servers',  kind: 'server',       risk: 0.118, state: 'norm',  tech: '—',             flows: 63 },
    { id: 'ext-src',  ip: '192.168.100.7', zone: 'External', kind: 'external', risk: 0.902, state: 'high', tech: 'T1110 source',  flows: 1210 },
    { id: 'ws-eng-01', ip: '10.0.10.21', zone: 'Workstations', kind: 'ws',      risk: 0.072, state: 'norm',  tech: '—',             flows: 51 },
    { id: 'ws-eng-02', ip: '10.0.10.22', zone: 'Workstations', kind: 'ws',      risk: 0.089, state: 'norm',  tech: '—',             flows: 47 },
    { id: 'ws-fin-01', ip: '10.0.10.41', zone: 'Workstations', kind: 'ws',      risk: 0.064, state: 'norm',  tech: '—',             flows: 39 },
    { id: 'ws-fin-02', ip: '10.0.10.42', zone: 'Workstations', kind: 'ws',      risk: 0.051, state: 'norm',  tech: '—',             flows: 36 },
    { id: 'ws-ops-01', ip: '10.0.10.61', zone: 'Workstations', kind: 'ws',      risk: 0.095, state: 'norm',  tech: '—',             flows: 44 },
    { id: 'plc-gw',   ip: '10.0.20.5',  zone: 'Critical', kind: 'ics',          risk: 0.033, state: 'norm',  tech: '—',             flows: 12 },
    { id: 'plc-01',   ip: '10.0.20.11', zone: 'Critical', kind: 'ics',          risk: 0.021, state: 'norm',  tech: '—',             flows: 8 }
  ];

  /* ---------- forecast branches ---------- */
  var BRANCHES = [
    { id: 'A', p: 66, tid: 'T1190', desc: 'Exploit the public-facing application', ttE: '+6s', asset: 'dmz-web', risk: 0.953, color: 'red' },
    { id: 'B', p: 23, tid: 'T1110', desc: 'Reuse harvested credentials on the VPN', ttE: '+12s', asset: 'srv-id', risk: 0.655, color: 'amber' },
    { id: 'C', p: 10, tid: '—', desc: 'Account lockout ends the attempt', ttE: '+8s', asset: 'external', risk: 0.120, color: 'dim' },
    { id: 'D', p: 1,  tid: 'T1046', desc: 'Service discovery residue only', ttE: '+14s', asset: 'srv-file', risk: 0.081, color: 'dim' }
  ];

  /* ---------- incidents ---------- */
  var INCIDENTS = [
    { id: 'INC-0142', sev: 'HIGH', status: 'TRIAGING', tid: 'T1110', tech: 'Brute Force', target: 'dmz-web', ip: '10.0.3.10', peak: 0.772, lead: 11.4, dur: '34s', analyst: 'a.rao', alerts: 147, opened: '19:48:42', evidence: 58 },
    { id: 'INC-0141', sev: 'MED',  status: 'CONTAINED', tid: 'T1046', tech: 'Network Service Discovery', target: 'srv-db', ip: '10.0.2.50', peak: 0.712, lead: 9.7, dur: '41s', analyst: 's.khan', alerts: 38, opened: '19:47:05', evidence: 24 },
    { id: 'INC-0138', sev: 'HIGH', status: 'CLOSED', tid: 'T1071.001', tech: 'Web Protocols', target: 'ws-eng-02', ip: '10.0.10.22', peak: 0.781, lead: 12.1, dur: '2m', analyst: 'n.iyer', alerts: 92, opened: '19:41:12', evidence: 61 },
    { id: 'INC-0140', sev: 'MED',  status: 'CLOSED', tid: 'T1110', tech: 'Brute Force', target: 'srv-file', ip: '10.0.2.30', peak: 0.694, lead: 8.9, dur: '1m', analyst: 'a.rao', alerts: 29, opened: '19:44:44', evidence: 19 }
  ];

  /* ---------- events ---------- */
  var EVENTS = [
    { ts: '19:44:52', sev: 'CRIT', src: 'inference', host: 'dmz-web', msg: 'Model risk 0.839 over threshold 0.65 — alert raised' },
    { ts: '19:44:47', sev: 'WARN', src: 'forecast',  host: 'dmz-web', msg: 'Forecast peak 0.953 at +16s — hazard onset inside horizon' },
    { ts: '19:44:41', sev: 'WARN', src: 'forecast',  host: 'dmz-web', msg: 'Early warning 6.8s ahead of InitialAccess milestone' },
    { ts: '19:44:36', sev: 'INFO', src: 'sensor',    host: '—',       msg: 'Window #90 sealed — 90 of 90 retained' },
    { ts: '19:44:31', sev: 'CRIT', src: 'inference', host: 'dmz-web', msg: 'Brute-force pattern: 147 failed auth flows in 34s' },
    { ts: '19:44:18', sev: 'INFO', src: 'sensor',    host: 'srv-app', msg: 'Flow volume nominal — 188 active flows' },
    { ts: '19:44:04', sev: 'WARN', src: 'rules',     host: 'srv-db',  msg: 'Lateral movement pattern matched — rule layer triggered' },
    { ts: '19:43:52', sev: 'INFO', src: 'model',     host: '—',       msg: 'Calibrated ExtraTrees inference latency 11.7 ms p95' },
    { ts: '19:43:29', sev: 'INFO', src: 'sensor',    host: '—',       msg: 'Capture-disjoint evaluation baseline loaded' }
  ];

  /* ---------- attack techniques by tactic (ATT&CK) ---------- */
  var ATTACK = [
    { tactic: 'Reconnaissance', items: [
      { id: 'T1595', name: 'Active Scanning', state: 'warm', p: 0.34 },
      { id: 'T1046', name: 'Network Service Discovery', state: 'warm', p: 0.41 },
      { id: 'T1592', name: 'Gather Host Information', state: '', p: 0.08 } ] },
    { tactic: 'Initial Access', items: [
      { id: 'T1190', name: 'Exploit Public-Facing App', state: 'hot', p: 0.83 },
      { id: 'T1110', name: 'Brute Force', state: 'hot', p: 0.66 },
      { id: 'T1078', name: 'Valid Accounts', state: 'warm', p: 0.22 } ] },
    { tactic: 'Execution', items: [
      { id: 'T1059', name: 'Command Interpreter', state: 'warm', p: 0.27 },
      { id: 'T1106', name: 'Native API', state: '', p: 0.09 } ] },
    { tactic: 'Command & Control', items: [
      { id: 'T1071.001', name: 'Web Protocols', state: 'warm', p: 0.19 },
      { id: 'T1571', name: 'Non-Standard Port', state: '', p: 0.06 } ] },
    { tactic: 'Lateral Movement', items: [
      { id: 'T1021', name: 'Remote Services', state: 'warm', p: 0.15 },
      { id: 'T1550', name: 'Alternate Auth Material', state: '', p: 0.05 } ] },
    { tactic: 'Exfiltration', items: [
      { id: 'T1041', name: 'Exfiltration Over C2', state: '', p: 0.08 },
      { id: 'T1048', name: 'Alt Protocol', state: '', p: 0.03 } ] },
    { tactic: 'Impact', items: [
      { id: 'T1489', name: 'Service Stop', state: '', p: 0.02 },
      { id: 'T1498', name: 'Network DoS', state: '', p: 0.11 } ] }
  ];

  /* ---------- campaign ---------- */
  var CAMPAIGN = {
    id: 'CMP-007 · BRUTE-FORCE → EXPLOIT CHAIN',
    started: '19:43:19', hosts: 4, flows: 1918, alerts: 307,
    stages: [
      { nm: 'Recon', ts: '19:43:19', done: true,  tid: 'T1046' },
      { nm: 'Access', ts: '19:44:22', done: true, tid: 'T1110' },
      { nm: 'Exec', ts: '—', done: false, tid: 'T1059' },
      { nm: 'C2', ts: '—', done: false, tid: 'T1071' },
      { nm: 'Lateral', ts: '—', done: false, tid: 'T1021' },
      { nm: 'Exfil', ts: '—', done: false, tid: 'T1041' },
      { nm: 'Impact', ts: '—', done: false, tid: 'T1489' }
    ]
  };

  /* ---------- predictions (technique head) ---------- */
  var PREDICTIONS = [
    { tid: 'T1190', name: 'Exploit Public-Facing Application', p: 0.833, eta: '+6s',  conf: '0.833' },
    { tid: 'T1110', name: 'Brute Force',                       p: 0.664, eta: '+12s', conf: '0.718' },
    { tid: 'T1046', name: 'Network Service Discovery',         p: 0.412, eta: '+3s',  conf: '0.655' },
    { tid: 'T1059', name: 'Command Interpreter',               p: 0.271, eta: '+14s', conf: '0.601' },
    { tid: 'T1071.001', name: 'Web Protocols',                 p: 0.198, eta: '+16s', conf: '0.577' },
    { tid: 'T1021', name: 'Remote Services',                   p: 0.152, eta: '+18s', conf: '0.544' },
    { tid: 'T1041', name: 'Exfiltration Over C2',              p: 0.084, eta: '+20s', conf: '0.512' },
    { tid: 'T1498', name: 'Network DoS',                       p: 0.031, eta: '+24s', conf: '0.498' }
  ];

  /* ---------- state vector (investigation) ---------- */
  var STATE_VECTOR = [
    { nm: 'H_emb_0', v: 0.335, hot: true }, { nm: 'H_emb_1', v: 0.389, hot: true },
    { nm: 'H_emb_2', v: 0.490, hot: true }, { nm: 'H_emb_3', v: 0.645, hot: true },
    { nm: 'H_emb_4', v: 0.689, hot: true }, { nm: 'H_emb_5', v: 0.618, hot: true },
    { nm: 'H_emb_6', v: 0.556, hot: true }, { nm: 'H_emb_7', v: 0.265 },
    { nm: 'H_emb_8', v: 0.369, hot: true }, { nm: 'H_emb_9', v: 0.161 },
    { nm: 'H_emb_10', v: 0.188 }, { nm: 'H_emb_11', v: 0.364 },
    { nm: 'flow_count', v: 0.225 }, { nm: 'fwd_bytes', v: 0.179 },
    { nm: 'bwd_bytes', v: 0.219 }, { nm: 'total_bytes', v: 0.199 },
    { nm: 'unique_peers', v: 0.151 }, { nm: 'syn_rate', v: 0.486, hot: true },
    { nm: 'pps', v: 0.312 }, { nm: 'dur_var', v: 0.094 }
  ];

  /* pristine snapshot of the fixtures: the loader merges live data over
     THIS copy so a later poll can always fall back to real fixtures
     (seeding from current FSDATA would let corrupted live data stick) */
  var FIXTURES = JSON.parse(JSON.stringify({
    ML: ML, windows: windows, OVERVIEW: OVERVIEW, HOSTS: HOSTS,
    BRANCHES: BRANCHES, INCIDENTS: INCIDENTS, EVENTS: EVENTS,
    ATTACK: ATTACK, CAMPAIGN: CAMPAIGN, PREDICTIONS: PREDICTIONS,
    STATE_VECTOR: STATE_VECTOR
  }));

  return {
    FIXTURES: FIXTURES,
    ML: ML, windows: windows, OVERVIEW: OVERVIEW, HOSTS: HOSTS,
    BRANCHES: BRANCHES, INCIDENTS: INCIDENTS, EVENTS: EVENTS,
    ATTACK: ATTACK, CAMPAIGN: CAMPAIGN, PREDICTIONS: PREDICTIONS,
    STATE_VECTOR: STATE_VECTOR
  };
})();
