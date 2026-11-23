/**
 * ============================================================================
 * Warden - Forensic Ledger Client Script
 * Zero external frameworks, 100% offline, strict textContent DOM rendering.
 * Real data only; empty state on missing data; no mock or simulated values.
 * ============================================================================
 */

(function () {
  'use strict';

  // State
  let currentNav = 'live';
  let eventSource = null;
  let highestSeenId = 0;
  let oldestSeenId = 0;
  let lastSealState = '';
  let isOffline = false;
  let pollFallbackInterval = null;
  let burstRateThreshold = 2.0; // default 20 in 10s

  // DOM Elements
  const banner = document.getElementById('connection-banner');
  const navLinks = document.querySelectorAll('.rail-nav-link');
  const pageViews = {
    live: document.getElementById('view-live'),
    ledger: document.getElementById('view-ledger'),
    report: document.getElementById('view-report'),
    system: document.getElementById('view-system')
  };

  // Format UNIX timestamp to HH:MM:SS
  function formatTime(epochSec) {
    if (!epochSec) return '--:--:--';
    const d = new Date(epochSec * 1000);
    const pad = (n) => (n < 10 ? '0' + n : n);
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  // Format relative time or seconds
  function formatUptime(seconds) {
    if (!seconds && seconds !== 0) return '--';
    const s = Math.floor(seconds);
    const hrs = Math.floor(s / 3600);
    const mins = Math.floor((s % 3600) / 60);
    const secs = s % 60;
    if (hrs > 0) return `${hrs}h ${mins}m ${secs}s`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
  }

  // Safe DOM Row Builder (Strictly textContent to prevent XSS from filenames)
  function createLedgerRowElement(ev, isNew) {
    const row = document.createElement('div');
    row.className = `ledger-row sev-${ev.severity || 'INFO'}`;
    if (isNew) {
      row.classList.add('row-highlight-new');
    }

    // 1. Time
    const timeCol = document.createElement('span');
    timeCol.className = 'lr-time';
    timeCol.textContent = formatTime(ev.ts);
    row.appendChild(timeCol);

    // 2. Type
    const typeCol = document.createElement('span');
    typeCol.className = 'lr-type';
    typeCol.textContent = ev.type || 'UNKNOWN';
    row.appendChild(typeCol);

    // 3. Path (split into dir and filename)
    const pathCol = document.createElement('span');
    pathCol.className = 'lr-path';
    const fullPath = ev.path || '';
    const slashIdx = fullPath.lastIndexOf('/');
    if (slashIdx !== -1) {
      const dirSpan = document.createElement('span');
      dirSpan.className = 'path-dir';
      dirSpan.textContent = fullPath.substring(0, slashIdx + 1);
      const fileSpan = document.createElement('span');
      fileSpan.className = 'path-file';
      fileSpan.textContent = fullPath.substring(slashIdx + 1);
      pathCol.appendChild(dirSpan);
      pathCol.appendChild(fileSpan);
    } else {
      const fileSpan = document.createElement('span');
      fileSpan.className = 'path-file';
      fileSpan.textContent = fullPath;
      pathCol.appendChild(fileSpan);
    }
    row.appendChild(pathCol);

    // 4. Detail
    const detailCol = document.createElement('span');
    detailCol.className = 'lr-detail';
    detailCol.textContent = ev.detail || '-';
    row.appendChild(detailCol);

    return row;
  }

  // Set Connection Error Banner
  function setConnectionStatus(connected) {
    if (connected) {
      if (isOffline) {
        isOffline = false;
        banner.classList.remove('visible');
        const pip = document.getElementById('rail-status-pip');
        if (pip) pip.classList.remove('inactive');
      }
    } else {
      if (!isOffline) {
        isOffline = true;
        banner.classList.add('visible');
        const pip = document.getElementById('rail-status-pip');
        if (pip) pip.classList.add('inactive');
      }
    }
  }

  // Active Threat & Warning Alert Box State
  let activeAlertLevel = null;
  let alertTimeoutId = null;

  function showAlert(level, title, message, epochSec) {
    const box = document.getElementById('ledger-alert-box');
    const badge = document.getElementById('alert-badge');
    const timeEl = document.getElementById('alert-timestamp');
    const msgEl = document.getElementById('alert-message');
    if (!box) return;

    // Critical alert takes precedence over warning
    if (activeAlertLevel === 'critical' && level === 'warning') {
      return;
    }

    activeAlertLevel = level;
    box.className = `ledger-alert-box level-${level}`;
    badge.textContent = title;
    timeEl.textContent = formatTime(epochSec || Math.floor(Date.now() / 1000));
    msgEl.textContent = message;
    box.style.display = 'flex';

    if (alertTimeoutId) clearTimeout(alertTimeoutId);
    if (level === 'warning') {
      alertTimeoutId = setTimeout(dismissAlert, 15000);
    }
  }

  function dismissAlert() {
    const box = document.getElementById('ledger-alert-box');
    if (box) box.style.display = 'none';
    activeAlertLevel = null;
    if (alertTimeoutId) {
      clearTimeout(alertTimeoutId);
      alertTimeoutId = null;
    }
  }

  // Update Integrity Seal
  function updateIntegritySeal(sealData) {
    const sealStamp = document.getElementById('seal-stamp');
    const sealWord = document.getElementById('seal-word');
    const sealHash = document.getElementById('seal-hash');
    const sealFiles = document.getElementById('seal-files');
    const sealDate = document.getElementById('seal-date');
    const sealDrift = document.getElementById('seal-drift-info');

    let state = (sealData.seal || 'missing').toLowerCase();
    const driftCount = sealData.drift_count || 0;

    // If baseline is sealed but files drifted, display DRIFT status
    if (state === 'sealed' && driftCount > 0) {
      state = 'drift';
    }

    // Check for state change to trigger thump
    if (lastSealState && lastSealState !== state) {
      sealStamp.classList.remove('thump');
      void sealStamp.offsetWidth; // trigger reflow
      sealStamp.classList.add('thump');
    }
    lastSealState = state;

    sealWord.className = `seal-word status-${state}`;
    if (state === 'sealed') {
      sealWord.textContent = 'SEALED';
    } else if (state === 'drift') {
      sealWord.textContent = `DRIFT (${driftCount})`;
    } else if (state === 'tampered') {
      sealWord.textContent = 'TAMPERED';
    } else {
      sealWord.textContent = 'MISSING';
    }

    const shortHash = sealData.hash ? sealData.hash.substring(0, 8) : 'NONE';
    sealHash.textContent = shortHash;
    sealFiles.textContent = sealData.files !== undefined ? sealData.files : '--';

    if (sealData.created && sealData.created > 0) {
      const d = new Date(sealData.created * 1000);
      sealDate.textContent = `CREATED: ${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')} ${formatTime(sealData.created)}`;
    } else {
      sealDate.textContent = 'CREATED: (NO BASELINE)';
    }

    sealDrift.textContent = `DRIFT: ${driftCount} file${driftCount === 1 ? '' : 's'} changed`;
  }

  // Draw Pulse Strip SVG
  function updatePulseStrip(bars60s) {
    const group = document.getElementById('pulse-bars-group');
    if (!group) return;
    while (group.firstChild) {
      group.removeChild(group.firstChild);
    }

    const maxVal = Math.max(burstRateThreshold * 1.5, ...bars60s, 5);
    const svgHeight = 64;
    const barWidth = 3.5;
    const barGap = 1.5;

    // Position threshold line
    const thresholdLine = document.getElementById('pulse-threshold-line');
    if (thresholdLine) {
      const lineY = Math.max(4, svgHeight - (burstRateThreshold / maxVal) * (svgHeight - 10));
      thresholdLine.setAttribute('y1', lineY.toFixed(1));
      thresholdLine.setAttribute('y2', lineY.toFixed(1));
    }

    bars60s.forEach((val, i) => {
      const x = i * (barWidth + barGap);
      const h = val > 0 ? Math.max(3, (val / maxVal) * (svgHeight - 10)) : 1;
      const y = svgHeight - h;

      const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      rect.setAttribute('x', x.toFixed(1));
      rect.setAttribute('y', y.toFixed(1));
      rect.setAttribute('width', barWidth.toString());
      rect.setAttribute('height', h.toFixed(1));
      rect.setAttribute('rx', '1.5');
      rect.setAttribute('ry', '1.5');

      if (val >= burstRateThreshold) {
        rect.setAttribute('fill', 'var(--bar-sakura-red)');
      } else if (val > 0) {
        rect.setAttribute('fill', 'var(--neon-green)');
      } else {
        rect.setAttribute('fill', '#0e2415');
      }
      group.appendChild(rect);
    });
  }

  // Poll /api/status
  async function fetchStatus() {
    try {
      const res = await fetch('/api/status');
      if (!res.ok) throw new Error(`Status HTTP ${res.status}`);
      const data = await res.json();
      setConnectionStatus(true);

      // Spec Strip
      const daemonState = document.getElementById('spec-daemon-state');
      const daemonSub = document.getElementById('spec-daemon-sub');
      const uptimeVal = document.getElementById('spec-uptime');
      const uptimeSub = document.getElementById('spec-uptime-sub');
      const queueVal = document.getElementById('spec-queue-val');
      const queueBar = document.getElementById('spec-queue-bar');
      const rateVal = document.getElementById('spec-rate-val');
      const totalEvents = document.getElementById('spec-events-total');

      if (data.daemon && data.daemon.running) {
        daemonState.textContent = 'RUNNING';
        daemonState.style.color = 'var(--oxide)';
        daemonSub.textContent = `PID: ${data.daemon.pid} (${data.daemon.threads} thr, ${data.daemon.rss_kb} KB)`;
      } else {
        daemonState.textContent = 'STOPPED';
        daemonState.style.color = 'var(--vermilion)';
        daemonSub.textContent = 'Daemon not running';
      }

      // Check stats.json freshness
      const statsObj = data.stats || {};
      if (statsObj.has_live_stats && statsObj.data) {
        const d = statsObj.data;
        uptimeVal.textContent = formatUptime(d.uptime);
        uptimeSub.textContent = `Age: ${statsObj.stats_age_sec}s (${d.workers || 4} workers)`;
        queueVal.textContent = `${d.queue_depth || 0} / ${d.queue_capacity || 1024}`;
        const pct = d.queue_capacity > 0 ? Math.min(100, (d.queue_depth / d.queue_capacity) * 100) : 0;
        queueBar.style.width = `${pct}%`;
        rateVal.textContent = `${(d.events_per_sec || 0).toFixed(1)} ev/s`;
        totalEvents.textContent = `Total: ${d.events_total || 0} events`;
      } else {
        uptimeVal.textContent = formatUptime(data.daemon.uptime_sec || 0);
        uptimeSub.textContent = 'NO LIVE STATS (watch stopped/idle)';
        queueVal.textContent = '0 / --';
        queueBar.style.width = '0%';
        rateVal.textContent = '0.0 ev/s';
      }

      if (data.burst_config && data.burst_config.rate_threshold) {
        burstRateThreshold = data.burst_config.rate_threshold;
        const rateLbl = document.getElementById('pulse-rate-label');
        if (rateLbl) rateLbl.textContent = `BURST THRESHOLD (${burstRateThreshold.toFixed(1)}/s)`;
      }

      // Update Integrity Seal
      if (data.baseline) {
        updateIntegritySeal(data.baseline);
      }

      // System view updates
      updateSystemView(data);

    } catch (err) {
      setConnectionStatus(false);
    }
  }

  // Poll /api/summary
  async function fetchSummary() {
    try {
      const res = await fetch('/api/summary');
      if (!res.ok) return;
      const summary = await res.json();

      // Pulse strip
      if (summary.pulse_60s) {
        updatePulseStrip(summary.pulse_60s);
      }

      // Breakdown bars
      const sevs = summary.counts_by_severity || {};
      const crit = sevs.CRITICAL || 0;
      const warn = sevs.WARNING || 0;
      const info = sevs.INFO || 0;
      const maxSev = Math.max(crit, warn, info, 1);

      document.getElementById('cnt-crit').textContent = crit;
      document.getElementById('bar-crit').style.width = `${(crit / maxSev) * 100}%`;
      document.getElementById('cnt-warn').textContent = warn;
      document.getElementById('bar-warn').style.width = `${(warn / maxSev) * 100}%`;
      document.getElementById('cnt-info').textContent = info;
      document.getElementById('bar-info').style.width = `${(info / maxSev) * 100}%`;

      // Report View updates
      updateReportView(summary);

    } catch (err) {
      // Ignore background summary error
    }
  }

  // Update Report View
  function updateReportView(summary) {
    const totalEl = document.getElementById('rep-total');
    const critEl = document.getElementById('rep-crit');
    const driftEl = document.getElementById('rep-drift');
    const tbody = document.getElementById('rep-top-paths-tbody');

    if (totalEl) totalEl.textContent = summary.total_events || 0;
    if (critEl) critEl.textContent = (summary.counts_by_severity && summary.counts_by_severity.CRITICAL) || 0;
    if (driftEl) driftEl.textContent = summary.drift_count || 0;

    if (tbody && summary.top_paths) {
      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      if (summary.top_paths.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 2;
        td.className = 'empty-ledger';
        td.textContent = 'No active file paths recorded.';
        tr.appendChild(td);
        tbody.appendChild(tr);
      } else {
        summary.top_paths.forEach(item => {
          const tr = document.createElement('tr');
          const tdPath = document.createElement('td');
          tdPath.textContent = item.path;
          const tdCount = document.createElement('td');
          tdCount.style.textAlign = 'right';
          tdCount.style.fontWeight = '600';
          tdCount.textContent = item.count;
          tr.appendChild(tdPath);
          tr.appendChild(tdCount);
          tbody.appendChild(tr);
        });
      }
    }
  }

  // Update System View
  function updateSystemView(data) {
    const sysState = document.getElementById('sys-daemon-state');
    const sysPid = document.getElementById('sys-daemon-pid');
    const sysUptime = document.getElementById('sys-daemon-uptime');
    const sysRss = document.getElementById('sys-daemon-rss');
    const sysThreads = document.getElementById('sys-daemon-threads');
    const sysRoots = document.getElementById('sys-roots-list');
    const sysSeal = document.getElementById('sys-seal-status');
    const sysHash = document.getElementById('sys-baseline-hash');
    const sysCount = document.getElementById('sys-baseline-count');
    const sysBurst = document.getElementById('sys-burst-cfg');
    const sysPort = document.getElementById('sys-web-port');
    const sysDir = document.getElementById('sys-web-dir');
    const repRoots = document.getElementById('rep-roots');

    if (sysState && data.daemon) {
      sysState.textContent = data.daemon.running ? 'RUNNING (Active inotify loop)' : 'STOPPED (Offline)';
      sysPid.textContent = data.daemon.pid || '--';
      sysUptime.textContent = formatUptime(data.daemon.uptime_sec);
      sysRss.textContent = data.daemon.rss_kb ? `${data.daemon.rss_kb} KB` : '--';
      sysThreads.textContent = data.daemon.threads || '--';
    }

    if (sysRoots && data.protected_roots) {
      while (sysRoots.firstChild) sysRoots.removeChild(sysRoots.firstChild);
      if (data.protected_roots.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'No protected directories configured.';
        sysRoots.appendChild(li);
      } else {
        data.protected_roots.forEach(r => {
          const li = document.createElement('li');
          li.textContent = `[DIR] ${r}`;
          sysRoots.appendChild(li);
        });
      }
      if (repRoots) repRoots.textContent = data.protected_roots.length;
    }

    if (data.baseline) {
      if (sysSeal) sysSeal.textContent = data.baseline.seal ? data.baseline.seal.toUpperCase() : '--';
      if (sysHash) sysHash.textContent = data.baseline.hash || '(None)';
      if (sysCount) sysCount.textContent = `${data.baseline.files || 0} files monitored`;
    }

    if (data.burst_config && sysBurst) {
      sysBurst.textContent = `${data.burst_config.threshold} events per ${data.burst_config.window_sec}s (${data.burst_config.rate_threshold.toFixed(1)}/s)`;
    }

    if (data.server) {
      if (sysPort) sysPort.textContent = data.server.port;
      if (sysDir) sysDir.textContent = data.server.web_dir;
    }
  }

  // Initialize highestSeenId to current end of log so LIVE view only shows new/current events
  async function initLiveBaselineOffset() {
    try {
      const res = await fetch('/api/events?limit=1');
      if (res.ok) {
        const events = await res.json();
        if (events && events.length > 0) {
          highestSeenId = events[0].id;
        }
      }
    } catch (err) {
      // Ignore initial offset fetch error
    }
  }

  // Setup Server-Sent Events (SSE) Stream
  function setupEventStream() {
    if (eventSource) {
      eventSource.close();
    }

    eventSource = new EventSource('/api/stream');

    eventSource.addEventListener('entry', (e) => {
      try {
        const ev = JSON.parse(e.data);
        if (!ev) return;
        setConnectionStatus(true);

        const container = document.getElementById('live-ledger-rows');
        const emptyEl = container.querySelector('.empty-ledger');
        if (emptyEl) {
          container.removeChild(emptyEl);
        }

        if (ev.id > highestSeenId) highestSeenId = ev.id;

        const rowEl = createLedgerRowElement(ev, true);
        container.insertBefore(rowEl, container.firstChild);

        // Cap to 50 rows in live view
        while (container.children.length > 50) {
          container.removeChild(container.lastChild);
        }

        // Display warning/threat alert banner
        if (ev.severity === 'CRITICAL') {
          if (ev.detail && ev.detail.includes('BURST ALERT')) {
            showAlert('critical', 'CRITICAL THREAT: MASS-TAMPER BURST DETECTED', ev.detail, ev.ts);
          } else {
            showAlert('critical', 'CRITICAL INTEGRITY VIOLATION', `${ev.type}: ${ev.path} — ${ev.detail}`, ev.ts);
          }
        } else if (ev.severity === 'WARNING') {
          showAlert('warning', 'SECURITY WARNING DETECTED', `${ev.type}: ${ev.path} — ${ev.detail}`, ev.ts);
        }

        // Trigger immediate stats/summary update
        fetchStatus();
        fetchSummary();
      } catch (err) {
        console.error('Error handling SSE entry:', err);
      }
    });

    eventSource.onerror = () => {
      setConnectionStatus(false);
      // Fallback: poll /api/events?after=<highestSeenId> every 1s
      if (!pollFallbackInterval) {
        pollFallbackInterval = setInterval(pollFallbackEvents, 1000);
      }
    };

    eventSource.onopen = () => {
      setConnectionStatus(true);
      if (pollFallbackInterval) {
        clearInterval(pollFallbackInterval);
        pollFallbackInterval = null;
      }
    };
  }

  // Fallback Polling if EventSource is disconnected
  async function pollFallbackEvents() {
    try {
      const url = highestSeenId > 0 ? `/api/events?after=${highestSeenId}&limit=50` : '/api/events?limit=50';
      const res = await fetch(url);
      if (!res.ok) throw new Error('Poll failed');
      const events = await res.json();
      setConnectionStatus(true);

      if (events && events.length > 0) {
        const container = document.getElementById('live-ledger-rows');
        const emptyEl = container.querySelector('.empty-ledger');
        if (emptyEl) container.removeChild(emptyEl);

        // Insert in order
        for (let i = events.length - 1; i >= 0; i--) {
          const ev = events[i];
          if (ev.id > highestSeenId) highestSeenId = ev.id;
          const rowEl = createLedgerRowElement(ev, true);
          container.insertBefore(rowEl, container.firstChild);
        }

        while (container.children.length > 50) {
          container.removeChild(container.lastChild);
        }
      }
    } catch (err) {
      setConnectionStatus(false);
    }
  }

  // Historical Ledger View Fetcher
  async function loadHistoryLedger(append = false) {
    const fType = document.getElementById('filt-type').value;
    const fSev = document.getElementById('filt-sev').value;
    const fSince = document.getElementById('filt-since').value.trim();
    const fPath = document.getElementById('filt-path').value.trim();

    let qs = new URLSearchParams();
    if (fType) qs.set('type', fType);
    if (fSev) qs.set('severity', fSev);
    if (fSince) qs.set('since', fSince);
    if (fPath) qs.set('path', fPath);
    qs.set('limit', '50');

    if (append && oldestSeenId > 0) {
      qs.set('before', oldestSeenId.toString());
    }

    // Update export CSV button href
    const exportBtn = document.getElementById('btn-export-csv');
    if (exportBtn) {
      const expQs = new URLSearchParams(qs);
      expQs.delete('limit');
      expQs.delete('before');
      exportBtn.href = `/api/export.csv?${expQs.toString()}`;
    }

    try {
      const res = await fetch(`/api/events?${qs.toString()}`);
      if (!res.ok) return;
      const events = await res.json();

      const container = document.getElementById('history-ledger-rows');
      const loadOlderBtn = document.getElementById('btn-load-older');

      if (!append) {
        while (container.firstChild) container.removeChild(container.firstChild);
        oldestSeenId = 0;
      }

      if (!events || events.length === 0) {
        if (!append) {
          const empty = document.createElement('div');
          empty.className = 'empty-ledger';
          empty.textContent = 'No entries. The ledger is quiet.';
          container.appendChild(empty);
        }
        if (loadOlderBtn) loadOlderBtn.style.display = 'none';
        return;
      }

      events.forEach(ev => {
        if (oldestSeenId === 0 || ev.id < oldestSeenId) {
          oldestSeenId = ev.id;
        }
        container.appendChild(createLedgerRowElement(ev, false));
      });

      if (loadOlderBtn) {
        loadOlderBtn.style.display = events.length >= 50 ? 'inline-block' : 'none';
      }
    } catch (err) {
      // Ignore filter error
    }
  }

  // Hash Router
  function switchPage(targetNav) {
    currentNav = targetNav;
    navLinks.forEach(link => {
      if (link.dataset.nav === targetNav) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    Object.keys(pageViews).forEach(key => {
      if (key === targetNav) {
        pageViews[key].classList.add('active');
      } else {
        pageViews[key].classList.remove('active');
      }
    });

    if (targetNav === 'ledger') {
      loadHistoryLedger(false);
    } else if (targetNav === 'report' || targetNav === 'system') {
      fetchStatus();
      fetchSummary();
    }
  }

  function handleHashChange() {
    const hash = window.location.hash.replace('#', '') || 'live';
    if (pageViews[hash]) {
      switchPage(hash);
    } else {
      switchPage('live');
    }
  }

  // Event Listeners
  window.addEventListener('hashchange', handleHashChange);

  document.getElementById('btn-apply-filter').addEventListener('click', () => {
    loadHistoryLedger(false);
  });

  document.getElementById('btn-reset-filter').addEventListener('click', () => {
    document.getElementById('filt-type').value = '';
    document.getElementById('filt-sev').value = '';
    document.getElementById('filt-since').value = '';
    document.getElementById('filt-path').value = '';
    loadHistoryLedger(false);
  });

  document.getElementById('btn-load-older').addEventListener('click', () => {
    loadHistoryLedger(true);
  });

  const ackBtn = document.getElementById('alert-ack-btn');
  if (ackBtn) {
    ackBtn.addEventListener('click', dismissAlert);
  }

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      dismissAlert();
    }
  });

  // Init
  handleHashChange();
  initLiveBaselineOffset();
  setupEventStream();
  fetchStatus();
  fetchSummary();

  // Status & Summary timers
  setInterval(fetchStatus, 2000);
  setInterval(fetchSummary, 3000);

})();
