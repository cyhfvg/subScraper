function getOverviewFilters() {
  try {
    const saved = localStorage.getItem('overviewFilters');
    return saved ? JSON.parse(saved) : {
      domainSearch: '',
      status: 'all'
    };
  } catch (e) {
    return {
      domainSearch: '',
      status: 'all'
    };
  }
}

function saveOverviewFiltersToStorage() {
  try {
    const domainSearch = document.getElementById('overview-domain-search')?.value || '';
    const status = document.getElementById('overview-status-filter')?.value || 'all';
    
    localStorage.setItem('overviewFilters', JSON.stringify({
      domainSearch,
      status
    }));
  } catch (e) {
    // Ignore localStorage errors
  }
}

function attachOverviewFilterListeners() {
  const domainSearch = document.getElementById('overview-domain-search');
  const statusFilter = document.getElementById('overview-status-filter');
  
  const applyFilters = () => {
    saveOverviewFiltersToStorage();
    renderOverviewTargets(latestTargetsData);
    renderJsFindingsOverview(latestTargetsData);
  };
  
  if (domainSearch) {
    domainSearch.addEventListener('input', applyFilters);
  }
  if (statusFilter) {
    statusFilter.addEventListener('change', applyFilters);
  }
}

function renderReports(targets) {
  latestTargetsData = targets || {};
  
  // Get filter values
  const filters = getReportFilters();
  
  const entries = Object.entries(latestTargetsData);
  if (!entries.length) {
    reportsBody.innerHTML = '<div class="section-placeholder">No reconnaissance data yet.</div>';
    selectedReportDomain = null;
    return;
  }
  
  // Apply filters
  const filteredEntries = entries.filter(([domain, info]) => {
    // Domain search filter
    if (filters.domainSearch && !domain.toLowerCase().includes(filters.domainSearch.toLowerCase())) {
      return false;
    }
    
    // Status filter (pending/complete)
    if (filters.status !== 'all') {
      const isPending = info && info.pending;
      if (filters.status === 'pending' && !isPending) return false;
      if (filters.status === 'complete' && isPending) return false;
    }
    
    // Severity filter
    if (filters.maxSeverity !== 'all') {
      const stats = computeReportStats(info || {});
      const severity = stats.maxSeverity || 'NONE';
      const severityLevels = ['NONE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const filterIndex = severityLevels.indexOf(filters.maxSeverity);
      const domainIndex = severityLevels.indexOf(severity);
      if (domainIndex < filterIndex) return false;
    }
    
    // Has findings filter
    if (filters.hasFindings) {
      const stats = computeReportStats(info || {});
      if (stats.nuclei === 0 && stats.nikto === 0) return false;
    }
    
    // Has screenshots filter
    if (filters.hasScreenshots) {
      const stats = computeReportStats(info || {});
      if (stats.screenshots === 0) return false;
    }
    
    return true;
  });
  
  // Sort filtered entries
  filteredEntries.sort((a, b) => {
    const aInfo = a[1] || {};
    const bInfo = b[1] || {};
    if (!!aInfo.pending !== !!bInfo.pending) {
      return aInfo.pending ? -1 : 1;
    }
    const aSubs = Object.keys(aInfo.subdomains || {}).length;
    const bSubs = Object.keys(bInfo.subdomains || {}).length;
    if (aSubs !== bSubs) return bSubs - aSubs;
    return a[0].localeCompare(b[0]);
  });
  
  if (!selectedReportDomain || !latestTargetsData[selectedReportDomain]) {
    selectedReportDomain = filteredEntries.length > 0 ? filteredEntries[0][0] : null;
  }
  
  const cards = filteredEntries.map(([domain, info]) => {
    const stats = computeReportStats(info || {});
    const badge = info && info.pending
      ? '<span class="report-badge pending">Pending</span>'
      : '<span class="report-badge complete">Complete</span>';
    const severity = stats.maxSeverity || 'NONE';
    const severityText = formatSeverityLabel(severity);
    const severityFlag = `<span class="severity-flag ${escapeHtml(severity)}">Max: ${escapeHtml(severityText)}</span>`;
    
    // Add completion timestamp if available
    // Only show timestamp for completed (non-pending) reports with a completion time
    let completedAtText = '';
    if (info && info.completed_at && !info.pending) {
      const completedDate = new Date(info.completed_at);
      const timeStr = completedDate.toLocaleString();
      completedAtText = `<span style="font-size: 11px; color: #94a3b8; display: block; margin-top: 4px;">Completed: ${escapeHtml(timeStr)}</span>`;
    }
    
    return `
      <div class="report-nav-card" data-report-domain="${escapeHtml(domain)}">
        <div class="domain-row">
          <div class="domain">${escapeHtml(domain)}</div>
          ${severityFlag}
        </div>
        <div class="meta">
          <span>Subs <span class="stat">${stats.subdomains}</span></span>
          <span>HTTP <span class="stat">${stats.http}</span></span>
          <span>Findings <span class="stat">${stats.nuclei + stats.nikto}</span></span>
        </div>
        ${badge}
        ${completedAtText}
      </div>
    `;
  }).join('');
  
  const filterControls = `
    <div class="filter-bar" style="margin-bottom: 16px; padding: 16px; background: var(--panel-alt); border-radius: 12px; border: 1px solid #1f2937;">
      <h3 style="margin: 0 0 12px 0; font-size: 14px; color: #93c5fd;">Filter Reports</h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Search Domain</label>
          <input type="search" id="report-domain-search" placeholder="example.com" value="${escapeHtml(filters.domainSearch || '')}" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
        </div>
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Status</label>
          <select id="report-status-filter" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
            <option value="all" ${filters.status === 'all' ? 'selected' : ''}>All</option>
            <option value="pending" ${filters.status === 'pending' ? 'selected' : ''}>Pending</option>
            <option value="complete" ${filters.status === 'complete' ? 'selected' : ''}>Complete</option>
          </select>
        </div>
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Min Severity</label>
          <select id="report-severity-filter" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
            <option value="all" ${filters.maxSeverity === 'all' ? 'selected' : ''}>All</option>
            <option value="INFO" ${filters.maxSeverity === 'INFO' ? 'selected' : ''}>Info+</option>
            <option value="LOW" ${filters.maxSeverity === 'LOW' ? 'selected' : ''}>Low+</option>
            <option value="MEDIUM" ${filters.maxSeverity === 'MEDIUM' ? 'selected' : ''}>Medium+</option>
            <option value="HIGH" ${filters.maxSeverity === 'HIGH' ? 'selected' : ''}>High+</option>
            <option value="CRITICAL" ${filters.maxSeverity === 'CRITICAL' ? 'selected' : ''}>Critical</option>
          </select>
        </div>
        <div style="display: flex; flex-direction: column; gap: 8px; justify-content: center;">
          <label style="font-size: 12px; display: flex; align-items: center; gap: 6px; cursor: pointer;">
            <input type="checkbox" id="report-has-findings" ${filters.hasFindings ? 'checked' : ''}>
            Has Findings
          </label>
          <label style="font-size: 12px; display: flex; align-items: center; gap: 6px; cursor: pointer;">
            <input type="checkbox" id="report-has-screenshots" ${filters.hasScreenshots ? 'checked' : ''}>
            Has Screenshots
          </label>
        </div>
      </div>
      <div style="margin-top: 8px; font-size: 12px; color: var(--muted);">
        Showing ${filteredEntries.length} of ${entries.length} reports
      </div>
    </div>
  `;
  
  reportsBody.innerHTML = `
    <div class="export-actions">
      <a class="btn" href="/api/export/state" target="_blank">Download JSON</a>
      <a class="btn secondary" href="/api/export/csv" target="_blank">Download CSV</a>
      <button class="btn" id="export-subdomains-txt">Export Subdomains (TXT)</button>
      <button class="btn secondary" id="export-subdomains-csv">Export Subdomains (CSV)</button>
    </div>
    ${filterControls}
    <div class="reports-layout">
      <div class="reports-nav" id="reports-nav">${cards}</div>
      <div class="report-detail" id="report-detail"></div>
    </div>
  `;
  
  // Attach filter event listeners
  attachReportFilterListeners();
  
  // Attach export subdomain button handlers
  const exportTxtBtn = document.getElementById('export-subdomains-txt');
  const exportCsvBtn = document.getElementById('export-subdomains-csv');
  
  if (exportTxtBtn) {
    exportTxtBtn.addEventListener('click', () => {
      const url = buildExportURLWithFilters('/api/export/subdomains/txt');
      window.open(url, '_blank');
    });
  }
  
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', () => {
      const url = buildExportURLWithFilters('/api/export/subdomains/csv');
      window.open(url, '_blank');
    });
  }
  
  renderReportDetail(selectedReportDomain);
}

function shouldSkipNikto(info) {
  const options = info && info.options || {};
  if (options.skip_nikto !== undefined) {
    return !!options.skip_nikto;
  }
  return !!(latestConfig && latestConfig.skip_nikto_by_default);
}

function renderCollapsibleSection(id, title, body, open = false) {
  return `
    <div class="collapsible ${open ? 'open' : ''}" data-collapsible="${escapeHtml(id)}">
      <button class="collapsible-header" type="button">
        <span>${escapeHtml(title)}</span>
        <span class="chevron">▶</span>
      </button>
      <div class="collapsible-body">
        ${body}
      </div>
    </div>
  `;
}

function buildStepChecklist(info) {
  const flags = info && info.flags ? info.flags : {};
  return STEP_SEQUENCE.map(step => {
    const skipped = step.skipWhen ? step.skipWhen(info) : false;
    const status = skipped ? 'skipped' : (flags[step.flag] ? 'completed' : 'pending');
    return `
      <div class="step">
        <span>${escapeHtml(step.label)}</span>
        <span class="status-pill ${statusClass(status)}">${statusLabel(status)}</span>
      </div>
    `;
  }).join('');
}

function monitorStatusClass(value) {
  switch (value) {
    case 'ok':
      return 'status-completed';
    case 'error':
      return 'status-error';
    case 'pending':
      return 'status-running';
    default:
      return 'status-skipped';
  }
}

function monitorStatusLabel(value) {
  if (!value) return 'Unknown';
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function renderMonitorEntries(entries) {
  if (!entries || !entries.length) {
    return '<tr><td colspan="5">No entries observed yet.</td></tr>';
  }
  return entries.map(entry => {
    const targets = (entry.dispatched_targets || []).join(', ') || '—';
    const status = entry.status || 'pending';
    return `
      <tr>
        <td>${escapeHtml(entry.value || '')}</td>
        <td>${escapeHtml(targets)}</td>
        <td><span class="status-pill ${statusClass(status)}">${statusLabel(status)}</span></td>
        <td>${fmtTime(entry.last_seen)}</td>
        <td>${escapeHtml(entry.dispatch_message || '—')}</td>
      </tr>
    `;
  }).join('');
}

function renderMonitors(monitors) {
  if (!monitorsList) return;
  monitorsData = Array.isArray(monitors) ? monitors : [];
  if (!monitorsData.length) {
    monitorsList.innerHTML = '<div class="section-placeholder">No monitors configured yet.</div>';
    return;
  }
  const cards = monitorsData.map(monitor => {
    const entries = Array.isArray(monitor.entries) ? monitor.entries : [];
    const entryRows = renderMonitorEntries(entries);
    const truncatedNote = monitor.entries_truncated ? '<p class="monitor-entry-note">Showing most recent entries.</p>' : '';
    const statusClassName = monitorStatusClass(monitor.last_status);
    const statusText = monitorStatusLabel(monitor.last_status);
    const errorMessage = monitor.last_error ? `<p class="status error">${escapeHtml(monitor.last_error)}</p>` : '';
    const nextCheck = monitor.next_check ? fmtTime(monitor.next_check) : 'Scheduled';
    return `
      <div class="monitor-card" data-monitor-id="${escapeHtml(monitor.id || '')}">
        <div class="monitor-header">
          <div>
            <h3>${escapeHtml(monitor.name || monitor.url || 'Monitor')}</h3>
            <div class="monitor-meta">
              <a href="${escapeHtml(monitor.url || '#')}" target="_blank">${escapeHtml(monitor.url || '')}</a><br>
              Interval: ${escapeHtml(monitor.interval || 0)}s · Last check: ${fmtTime(monitor.last_checked)} · Next check: ${nextCheck}
            </div>
          </div>
          <div class="monitor-actions">
            <span class="status-pill ${statusClassName}">${statusText}</span>
            <button class="btn secondary small" data-remove-monitor="${escapeHtml(monitor.id || '')}">Remove</button>
          </div>
        </div>
        <div class="monitor-stats">
          <span>Entries: ${escapeHtml(monitor.entry_count || 0)}</span>
          <span>Pending: ${escapeHtml(monitor.pending_entries || 0)}</span>
          <span>Last new: ${escapeHtml(monitor.last_new_entries || 0)}</span>
          <span>Last dispatched: ${escapeHtml(monitor.last_dispatch_count || 0)}</span>
        </div>
        ${errorMessage}
        <div class="table-wrapper">
          <table class="monitor-entry-table">
            <thead>
              <tr>
                <th>Value</th>
                <th>Targets</th>
                <th>Status</th>
                <th>Last seen</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>${entryRows}</tbody>
          </table>
        </div>
        ${truncatedNote}
      </div>
    `;
  }).join('');
  monitorsList.innerHTML = cards;
}

async function deleteMonitor(id, button) {
  if (!id) return;
  const original = button ? button.textContent : null;
  if (button) {
    button.disabled = true;
    button.textContent = 'Removing…';
  }
  try {
    const resp = await fetch('/api/monitors/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    const data = await resp.json();
    if (!data.success) {
      throw new Error(data.message || 'Failed to remove monitor.');
    }
    if (monitorStatus) {
      monitorStatus.textContent = data.message || 'Monitor removed.';
      monitorStatus.className = 'status success';
    }
    fetchState();
  } catch (err) {
    if (monitorStatus) {
      monitorStatus.textContent = err.message || 'Failed to remove monitor.';
      monitorStatus.className = 'status error';
    }
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = original;
    }
  }
}

function updateReportNavSelection() {
  const nav = document.getElementById('reports-nav');
  if (!nav) return;
  nav.querySelectorAll('.report-nav-card').forEach(card => {
    card.classList.toggle('active', card.dataset.reportDomain === selectedReportDomain);
  });
}

function buildSubdomainRows(info) {
  const subs = info.subdomains || {};
  const hosts = Object.keys(subs).sort();
  return hosts.map(host => {
    const entry = subs[host] || {};
    const httpx = entry.httpx || {};
    const statusCode = httpx.status_code !== undefined && httpx.status_code !== null ? String(httpx.status_code) : '';
    return {
      host,
      sources: entry.sources || [],
      statusCode,
      title: httpx.title || '',
      server: httpx.webserver || '',
      screenshot: entry.screenshot,
      nucleiCount: Array.isArray(entry.nuclei) ? entry.nuclei.length : 0,
      niktoCount: Array.isArray(entry.nikto) ? entry.nikto.length : 0,
      url: httpx.url || '',
    };
  });
}

function buildStatusFilterOptions(rows) {
  const statuses = new Set();
  rows.forEach(row => statuses.add(row.statusCode || 'none'));
  return Array.from(statuses).sort((a, b) => {
    if (a === 'none') return 1;
    if (b === 'none') return -1;
    return Number(a) - Number(b);
  });
}

function buildNucleiRows(info) {
  const rows = [];
  const subs = info.subdomains || {};
  Object.entries(subs).forEach(([host, entry]) => {
    (entry.nuclei || []).forEach(finding => {
      const severity = normalizeSeverity(finding && finding.severity, 'INFO');
      rows.push({
        host,
        severity,
        template: finding.template_id || finding["template-id"] || 'N/A',
        name: finding.name || '',
        location: finding.matched_at || finding["matched-at"] || finding.url || '',
      });
    });
  });
  return rows;
}

