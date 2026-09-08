function buildNiktoRows(info) {
  const rows = [];
  const subs = info.subdomains || {};
  Object.entries(subs).forEach(([host, entry]) => {
    (entry.nikto || []).forEach(finding => {
      const severity = normalizeSeverity((finding && (finding.severity || finding.risk)) || 'INFO', 'INFO');
      rows.push({
        host,
        severity,
        message: finding.msg || finding.description || finding.raw || '',
        reference: finding.uri || (finding.osvdb ? `OSVDB-${finding.osvdb}` : ''),
      });
    });
  });
  return rows;
}

async function renderReportDetail(domain) {
  const detail = document.getElementById('report-detail');
  if (!detail) return;
  
  // Show loading state
  detail.innerHTML = '<div class="section-placeholder">Loading full report data...</div>';
  
  // Fetch full domain data from API (not truncated summary)
  let info;
  try {
    const resp = await fetch(`/api/domain/${encodeURIComponent(domain)}`);
    if (!resp.ok) throw new Error('Failed to load domain data');
    const data = await resp.json();
    if (!data.success) throw new Error(data.message || 'Failed to load data');
    info = data.data;
    
    // Update latestTargetsData with full data so it's available for future use
    latestTargetsData[domain] = info;
    
    // Set selected domain only after successful load
    selectedReportDomain = domain;
    updateReportNavSelection();
  } catch (err) {
    detail.innerHTML = `<div class="section-placeholder">Error loading report: ${escapeHtml(err.message)}</div>`;
    return;
  }
  const stats = computeReportStats(info);
  const badge = info.pending
    ? '<span class="report-badge pending">Pending</span>'
    : '<span class="report-badge complete">Complete</span>';
  const maxSeverity = stats.maxSeverity || 'NONE';
  const maxSeverityText = formatSeverityLabel(maxSeverity);
  const maxSeverityFlag = `<span class="severity-flag ${escapeHtml(maxSeverity)}">Max: ${escapeHtml(maxSeverityText)}</span>`;
  const maxNucleiSeverity = stats.maxNucleiSeverity || 'NONE';
  const maxNucleiSeverityText = formatSeverityLabel(maxNucleiSeverity);
  const maxNucleiSeverityFlag = `<span class="severity-flag ${escapeHtml(maxNucleiSeverity)}">Nuclei: ${escapeHtml(maxNucleiSeverityText)}</span>`;
  const maxNiktoSeverity = stats.maxNiktoSeverity || 'NONE';
  const maxNiktoSeverityText = formatSeverityLabel(maxNiktoSeverity);
  const maxNiktoSeverityFlag = `<span class="severity-flag ${escapeHtml(maxNiktoSeverity)}">Nikto: ${escapeHtml(maxNiktoSeverityText)}</span>`;
  const activeJob = hasActiveJob(domain);
  const canResume = info.pending && !activeJob;
  const resumeButton = canResume ? `<button class="btn small" data-resume-target="${escapeHtml(domain)}">Resume Scan</button>` : '';
  const resumeNotice = info.pending && activeJob ? '<span class="muted">Scan already active for this program.</span>' : '';
  const subRows = buildSubdomainRows(info);
  const statusOptions = buildStatusFilterOptions(subRows);
  const statusFilters = statusOptions.length
    ? statusOptions.map(code => {
        const label = code === 'none' ? 'No status' : code;
        return `<label><input type="checkbox" value="${escapeHtml(code)}" checked />${escapeHtml(label)}</label>`;
      }).join('')
    : '<span class="muted">No HTTP data yet.</span>';
  const subTableRows = subRows.length
    ? subRows.map(row => {
        const statusCode = row.statusCode || '';
        const screenshotLink = row.screenshot && row.screenshot.path
          ? `<a href="/screenshots/${escapeHtml(row.screenshot.path)}" target="_blank">View</a>`
          : '—';
        return `
          <tr data-status-code="${statusCode || 'none'}" data-host="${escapeHtml(row.host.toLowerCase())}" data-title="${escapeHtml((row.title || '').toLowerCase())}">
            <td data-sort-value="${escapeHtml(row.host)}"><a href="/subdomain/${encodeURIComponent(domain)}/${encodeURIComponent(row.host)}" class="link-btn">${escapeHtml(row.host)}</a></td>
            <td data-sort-value="${statusCode || '0'}">${statusCode || '—'}</td>
            <td data-sort-value="${escapeHtml((row.title || '').toLowerCase())}">${escapeHtml(row.title || '—')}</td>
            <td data-sort-value="${escapeHtml((row.server || '').toLowerCase())}">${escapeHtml(row.server || '—')}</td>
            <td data-sort-value="${row.screenshot ? '1' : '0'}">${screenshotLink}</td>
            <td data-sort-value="${row.nucleiCount}">${row.nucleiCount ? `${row.nucleiCount} findings` : '—'}</td>
            <td data-sort-value="${row.niktoCount}">${row.niktoCount ? `${row.niktoCount} findings` : '—'}</td>
            <td data-sort-value="${escapeHtml((row.sources || []).join(', ').toLowerCase())}">${escapeHtml((row.sources || []).join(', ')) || '—'}</td>
          </tr>
        `;
      }).join('')
    : '<tr><td colspan="8">No subdomains collected yet.</td></tr>';
  const nucleiRows = buildNucleiRows(info);
  const nucleiSeverities = Array.from(new Set(nucleiRows.map(row => row.severity))).sort();
  const nucleiFilters = nucleiSeverities.length
    ? nucleiSeverities.map(sev => `<label><input type="checkbox" value="${escapeHtml(sev)}" checked />${escapeHtml(sev)}</label>`).join('')
    : '';
  const nucleiTableRows = nucleiRows.length
    ? nucleiRows.map(row => `
        <tr data-severity="${escapeHtml(row.severity)}">
          <td data-sort-value="${escapeHtml(row.severity)}"><span class="severity-pill ${escapeHtml(row.severity)}">${escapeHtml(row.severity)}</span></td>
          <td data-sort-value="${escapeHtml(row.host.toLowerCase())}">${escapeHtml(row.host)}</td>
          <td data-sort-value="${escapeHtml((row.template || '').toLowerCase())}">${escapeHtml(row.template || 'N/A')}</td>
          <td data-sort-value="${escapeHtml((row.name || '').toLowerCase())}">${escapeHtml(row.name || '—')}</td>
          <td data-sort-value="${escapeHtml((row.location || '').toLowerCase())}">${escapeHtml(row.location || '—')}</td>
        </tr>
      `).join('')
    : '';
  const niktoRows = buildNiktoRows(info);
  const niktoSeverities = Array.from(new Set(niktoRows.map(row => row.severity))).sort();
  const niktoFilters = niktoSeverities.length
    ? niktoSeverities.map(sev => `<label><input type="checkbox" value="${escapeHtml(sev)}" checked />${escapeHtml(sev)}</label>`).join('')
    : '';
  const niktoTableRows = niktoRows.length
    ? niktoRows.map(row => `
        <tr data-severity="${escapeHtml(row.severity)}">
          <td data-sort-value="${escapeHtml(row.severity)}"><span class="severity-pill ${escapeHtml(row.severity)}">${escapeHtml(row.severity)}</span></td>
          <td data-sort-value="${escapeHtml(row.host.toLowerCase())}">${escapeHtml(row.host)}</td>
          <td data-sort-value="${escapeHtml((row.message || '').toLowerCase())}">${escapeHtml(row.message || '—')}</td>
          <td data-sort-value="${escapeHtml((row.reference || '').toLowerCase())}">${escapeHtml(row.reference || '—')}</td>
        </tr>
      `).join('')
    : '';
  const overviewBody = `
    <div class="progress-track">
      <div class="label">Run progress</div>
      <div class="progress-bar"><div class="progress-inner" style="width:${stats.progress}%"></div></div>
      <div class="muted">${stats.progress}% complete (${stats.processed_subdomains}/${stats.subdomains || 0} fully processed)</div>
    </div>
    <div class="report-stats-grid">
      <div class="report-stat">
        <div class="label">Subdomains</div>
        <div class="value">${stats.subdomains}</div>
      </div>
      <div class="report-stat">
        <div class="label">HTTP entries</div>
        <div class="value">${stats.http}</div>
      </div>
      <div class="report-stat">
        <div class="label">Nuclei findings</div>
        <div class="value">${stats.nuclei}</div>
      </div>
      <div class="report-stat">
        <div class="label">Nikto findings</div>
        <div class="value">${stats.nikto}</div>
      </div>
      <div class="report-stat">
        <div class="label">Screenshots</div>
        <div class="value">${stats.screenshots}</div>
      </div>
      <div class="report-stat">
        <div class="label">Max severity (Overall)</div>
        <div class="value">${maxSeverityFlag}</div>
      </div>
      <div class="report-stat">
        <div class="label">Highest Nuclei</div>
        <div class="value">${maxNucleiSeverityFlag}</div>
      </div>
      <div class="report-stat">
        <div class="label">Highest Nikto</div>
        <div class="value">${maxNiktoSeverityFlag}</div>
      </div>
    </div>
    <div class="report-stats-grid">
      <div class="report-stat">
        <div class="label">Pending subdomains</div>
        <div class="value">${stats.pending_subdomains}</div>
      </div>
      <div class="report-stat">
        <div class="label">Pending HTTP</div>
        <div class="value">${stats.pending_http}</div>
      </div>
      <div class="report-stat">
        <div class="label">Pending screenshots</div>
        <div class="value">${stats.pending_screenshots}</div>
      </div>
      <div class="report-stat">
        <div class="label">Pending nuclei</div>
        <div class="value">${stats.pending_nuclei}</div>
      </div>
      <div class="report-stat">
        <div class="label">Pending nikto</div>
        <div class="value">${stats.pending_nikto}</div>
      </div>
    </div>
    <div class="step-checklist">
      ${buildStepChecklist(info)}
    </div>
  `;
  // Endpoints section (URLs from waybackurls and gau)
  const endpoints = info.endpoints || [];
  const endpointsTitle = `Endpoints (${endpoints.length})`;
  const endpointsBody = endpoints.length > 0 ? `
    <div class="filter-bar">
      <input type="search" class="report-search" placeholder="Search endpoints…" data-endpoint-search />
    </div>
    <div class="table-wrapper">
      <table class="targets-table" id="endpoints-table">
        <thead>
          <tr>
            <th>URL</th>
          </tr>
        </thead>
        <tbody>
          ${endpoints.slice(0, 500).map(url => `
            <tr data-endpoint="${escapeHtml(url.toLowerCase())}">
              <td><a href="${escapeHtml(url)}" target="_blank" class="link-btn">${escapeHtml(url)}</a></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
    ${endpoints.length > 500 ? `<p class="muted">Showing first 500 of ${endpoints.length} endpoints</p>` : ''}
    <div class="table-pagination" id="endpoints-pagination"></div>
  ` : '<p class="muted">No endpoints discovered yet.</p>';
  
  const subPaginationId = 'subdomains-pagination';
  const nucleiPaginationId = 'nuclei-pagination';
  const niktoPaginationId = 'nikto-pagination';
  const subdomainsTitle = `Subdomains (${stats.subdomains})`;
  const nucleiTitle = `Nuclei Findings (${nucleiRows.length})`;
  const niktoTitle = `Nikto Findings (${niktoRows.length})`;
  const subdomainsBody = `
    <div class="filter-bar">
      <div class="filter-group" data-status-filter>
        ${statusFilters}
      </div>
      <input type="search" class="report-search" placeholder="Search subdomains…" data-sub-search />
      <div style="display: flex; gap: 6px; margin-left: auto; align-items: center; flex-shrink: 0;">
        <button class="btn small secondary" id="report-detail-export-txt" title="Export filtered subdomains as plain text">Export TXT</button>
        <button class="btn small secondary" id="report-detail-export-csv" title="Export filtered subdomains as CSV">Export CSV</button>
      </div>
    </div>
    <div class="table-wrapper">
      <table class="targets-table" id="subdomains-table">
        <thead>
          <tr>
            <th data-sort-key="host">Subdomain</th>
            <th data-sort-key="status" data-sort-type="number">Status</th>
            <th data-sort-key="title">Title</th>
            <th data-sort-key="server">Server</th>
            <th data-sort-key="screenshot" data-sort-type="number">Screenshot</th>
            <th data-sort-key="nuclei" data-sort-type="number">Nuclei</th>
            <th data-sort-key="nikto" data-sort-type="number">Nikto</th>
            <th data-sort-key="sources">Sources</th>
          </tr>
        </thead>
        <tbody>${subTableRows}</tbody>
      </table>
    </div>
    <div class="table-pagination" id="${subPaginationId}"></div>
    <p class="report-table-note">Click a subdomain to explore its detailed timeline.</p>
  `;
  const nucleiContent = nucleiRows.length ? `
    ${nucleiRows.length ? `<div class="filter-bar" data-nuclei-filter><div class="filter-group">${nucleiFilters}</div></div>` : ''}
    <div class="table-wrapper">
      <table class="targets-table" id="nuclei-table">
        <thead>
          <tr>
            <th data-sort-key="severity">Severity</th>
            <th data-sort-key="host">Host</th>
            <th data-sort-key="template">Template</th>
            <th data-sort-key="name">Name</th>
            <th data-sort-key="location">Matched</th>
          </tr>
        </thead>
        <tbody>${nucleiTableRows}</tbody>
      </table>
    </div>
    <div class="table-pagination" id="${nucleiPaginationId}"></div>
  ` : '<p class="muted">No nuclei findings recorded.</p>';
  const niktoContent = niktoRows.length ? `
    ${niktoRows.length ? `<div class="filter-bar" data-nikto-filter><div class="filter-group">${niktoFilters}</div></div>` : ''}
    <div class="table-wrapper">
      <table class="targets-table" id="nikto-table">
        <thead>
          <tr>
            <th data-sort-key="severity">Severity</th>
            <th data-sort-key="host">Host</th>
            <th data-sort-key="message">Message</th>
            <th data-sort-key="reference">Reference</th>
          </tr>
        </thead>
        <tbody>${niktoTableRows}</tbody>
      </table>
    </div>
    <div class="table-pagination" id="${niktoPaginationId}"></div>
  ` : '<p class="muted">No Nikto findings recorded.</p>';
  // JS scan section (secrets, endpoints, params gathered from JS assets)
  const jsScan = info.js_scan || null;
  const jsSecrets = (jsScan && jsScan.secrets) || [];
  const jsEndpoints = (jsScan && jsScan.endpoints) || [];
  const jsParams = (jsScan && jsScan.params) || [];
  const jsFiles = (jsScan && jsScan.files) || [];
  const jsSummary = (jsScan && jsScan.summary) || {};
  const jsScanTitle = `JS Findings (${jsSecrets.length} secrets, ${jsEndpoints.length} endpoints)`;
  const jsScanBody = jsScan ? `
    <div class="report-stats-grid">
      <div class="report-stat"><div class="label">JS files scanned</div><div class="value">${jsSummary.files_ok || 0}/${jsSummary.files || 0}</div></div>
      <div class="report-stat"><div class="label">Secrets</div><div class="value">${jsSecrets.length}</div></div>
      <div class="report-stat"><div class="label">Endpoints</div><div class="value">${jsEndpoints.length}</div></div>
      <div class="report-stat"><div class="label">Parameters</div><div class="value">${jsParams.length}</div></div>
    </div>
    ${jsScan.truncated ? '<p class="muted">Note: JS file list was truncated to the configured limit.</p>' : ''}
    <h4 style="margin:16px 0 6px;">Secrets & Keys</h4>
    ${jsSecrets.length > 0 ? `
    <div class="table-wrapper">
      <table class="targets-table" id="js-secrets-table">
        <thead><tr><th>Type</th><th>Match (redacted)</th><th>Source</th></tr></thead>
        <tbody>
          ${jsSecrets.slice(0, 500).map(s => `
            <tr>
              <td><span class="badge">${escapeHtml(s.type || '')}</span></td>
              <td><code>${escapeHtml(s.match || '')}</code></td>
              <td><a href="${escapeHtml(s.source || '#')}" target="_blank" class="link-btn">${escapeHtml(s.source || '')}</a></td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>
    <div class="table-pagination" id="js-secrets-pagination"></div>
    ` : '<p class="muted">No secrets or keys detected in JS.</p>'}
    <h4 style="margin:16px 0 6px;">Discovered Endpoints</h4>
    ${jsEndpoints.length > 0 ? `
    <div class="filter-bar">
      <input type="search" class="report-search" placeholder="Search JS endpoints…" data-js-endpoint-search />
    </div>
    <div class="table-wrapper">
      <table class="targets-table" id="js-endpoints-table">
        <thead><tr><th>Endpoint</th></tr></thead>
        <tbody>
          ${jsEndpoints.slice(0, 1000).map(ep => `
            <tr data-js-endpoint="${escapeHtml((ep || '').toLowerCase())}">
              <td><code>${escapeHtml(ep)}</code></td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>
    ${jsEndpoints.length > 1000 ? `<p class="muted">Showing first 1000 of ${jsEndpoints.length} endpoints</p>` : ''}
    <div class="table-pagination" id="js-endpoints-pagination"></div>
    ` : '<p class="muted">No hidden endpoints found in JS.</p>'}
    <h4 style="margin:16px 0 6px;">Parameters</h4>
    ${jsParams.length > 0
      ? `<div>${jsParams.slice(0, 500).map(p => `<span class="badge" style="margin:2px;">${escapeHtml(p)}</span>`).join(' ')}</div>`
      : '<p class="muted">No parameters extracted.</p>'}
    <h4 style="margin:16px 0 6px;">JS Files</h4>
    ${jsFiles.length > 0 ? `
    <div class="table-wrapper">
      <table class="targets-table" id="js-files-table">
        <thead><tr><th>URL</th><th>OK</th><th>Size</th><th>Secrets</th><th>Endpoints</th></tr></thead>
        <tbody>
          ${jsFiles.slice(0, 500).map(f => `
            <tr>
              <td><a href="${escapeHtml(f.url || '#')}" target="_blank" class="link-btn">${escapeHtml(f.url || '')}</a></td>
              <td>${f.ok ? '✅' : '❌'}</td>
              <td>${f.size || 0}</td>
              <td>${f.secrets || 0}</td>
              <td>${f.endpoints || 0}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>
    <div class="table-pagination" id="js-files-pagination"></div>
    ` : '<p class="muted">No JS files fetched.</p>'}
  ` : '<p class="muted">JS scan has not run for this target yet.</p>';

  const commandsBody = `
    <div data-command-log data-command-domain="${escapeHtml(domain)}">
      <p class="muted">Loading command history…</p>
    </div>
  `;
  detail.innerHTML = `
    <div class="report-header">
      <div>
        <h3>${escapeHtml(domain)}</h3>
        ${badge}
      </div>
      <div class="report-actions">
        <a href="/domain/${encodeURIComponent(domain)}" class="btn small" target="_blank">View Domain Details</a>
        ${stats.screenshots > 0 ? `<a href="/gallery/${encodeURIComponent(domain)}" class="btn secondary small" target="_blank">View Screenshots Gallery</a>` : ''}
        <button class="btn secondary small" data-js-scan-btn data-domain="${escapeHtml(domain)}">Run JS Scan</button>
        ${resumeButton}
        ${resumeNotice}
      </div>
    </div>
    ${renderCollapsibleSection('overview', 'Overview', overviewBody, true)}
    ${renderCollapsibleSection('subdomains', subdomainsTitle, subdomainsBody, true)}
    ${endpoints.length > 0 ? renderCollapsibleSection('endpoints', endpointsTitle, endpointsBody, false) : ''}
    ${renderCollapsibleSection('nuclei', nucleiTitle, nucleiContent, nucleiRows.length > 0)}
    ${renderCollapsibleSection('jsscan', jsScanTitle, jsScanBody, jsSecrets.length > 0)}
    ${renderCollapsibleSection('nikto', niktoTitle, niktoContent, false)}
    ${renderCollapsibleSection('commands', 'Command History', commandsBody, false)}
  `;
  makeSortable(detail.querySelector('#subdomains-table'));
  makeSortable(detail.querySelector('#nuclei-table'));
  makeSortable(detail.querySelector('#nikto-table'));
  initPagination(detail.querySelector('#subdomains-table'), detail.querySelector('#' + subPaginationId), DEFAULT_PAGE_SIZE);
  initPagination(detail.querySelector('#nuclei-table'), detail.querySelector('#' + nucleiPaginationId), DEFAULT_PAGE_SIZE);
  initPagination(detail.querySelector('#nikto-table'), detail.querySelector('#' + niktoPaginationId), DEFAULT_PAGE_SIZE);
  if (endpoints.length > 0) {
    initPagination(detail.querySelector('#endpoints-table'), detail.querySelector('#endpoints-pagination'), DEFAULT_PAGE_SIZE);
    attachEndpointFilter(detail);
  }
  if (jsSecrets.length > 0) {
    initPagination(detail.querySelector('#js-secrets-table'), detail.querySelector('#js-secrets-pagination'), DEFAULT_PAGE_SIZE);
  }
  if (jsEndpoints.length > 0) {
    initPagination(detail.querySelector('#js-endpoints-table'), detail.querySelector('#js-endpoints-pagination'), DEFAULT_PAGE_SIZE);
    const jsSearch = detail.querySelector('[data-js-endpoint-search]');
    const jsTable = detail.querySelector('#js-endpoints-table');
    if (jsSearch && jsTable) {
      jsSearch.addEventListener('input', () => {
        const q = jsSearch.value.trim().toLowerCase();
        const rows = jsTable.tBodies[0] ? Array.from(jsTable.tBodies[0].rows) : [];
        rows.forEach(row => {
          const ep = row.dataset.jsEndpoint || '';
          row.dataset.filterHidden = (!q || ep.includes(q)) ? 'false' : 'true';
        });
        refreshPagination(jsTable);
      });
    }
  }
  if (jsFiles.length > 0) {
    initPagination(detail.querySelector('#js-files-table'), detail.querySelector('#js-files-pagination'), DEFAULT_PAGE_SIZE);
  }
  const jsScanBtn = detail.querySelector('[data-js-scan-btn]');
  if (jsScanBtn) {
    jsScanBtn.addEventListener('click', async () => {
      jsScanBtn.disabled = true;
      const orig = jsScanBtn.textContent;
      jsScanBtn.textContent = 'Scanning…';
      try {
        const resp = await fetch('/api/domain/js-scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: jsScanBtn.getAttribute('data-domain') }),
        });
        const data = await resp.json();
        jsScanBtn.textContent = data.success ? 'Scan started ✓' : 'Failed';
        setTimeout(() => { jsScanBtn.textContent = orig; jsScanBtn.disabled = false; }, 4000);
      } catch (err) {
        jsScanBtn.textContent = 'Error';
        setTimeout(() => { jsScanBtn.textContent = orig; jsScanBtn.disabled = false; }, 4000);
      }
    });
  }
  attachSubdomainFilters(detail);
  attachSeverityFilter(detail.querySelector('[data-nuclei-filter]'), detail.querySelector('#nuclei-table'));
  attachSeverityFilter(detail.querySelector('[data-nikto-filter]'), detail.querySelector('#nikto-table'));
  
  // Wire up per-report subdomain export buttons
  const exportTxtBtn = detail.querySelector('#report-detail-export-txt');
  const exportCsvBtn = detail.querySelector('#report-detail-export-csv');
  const buildReportExportURL = (format) => {
    const statusGroup = detail.querySelector('[data-status-filter]');
    const searchInput = detail.querySelector('[data-sub-search]');
    const params = new URLSearchParams();
    params.set('domain', domain);
    const subSearch = (searchInput && searchInput.value || '').trim();
    if (subSearch) params.set('subSearch', subSearch);
    const activeCodes = statusGroup
      ? Array.from(statusGroup.querySelectorAll('input[type="checkbox"]'))
          .filter(cb => cb.checked).map(cb => cb.value)
      : [];
    const allCodes = statusGroup
      ? Array.from(statusGroup.querySelectorAll('input[type="checkbox"]'))
          .map(cb => cb.value)
      : [];
    if (activeCodes.length && activeCodes.length < allCodes.length) {
      params.set('statusCodes', activeCodes.join(','));
    }
    return `/api/export/subdomains/${format}?${params.toString()}`;
  };
  if (exportTxtBtn) {
    exportTxtBtn.addEventListener('click', () => window.open(buildReportExportURL('txt'), '_blank'));
  }
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', () => window.open(buildReportExportURL('csv'), '_blank'));
  }
  
  hydrateCommandLog(domain);
  updateReportNavSelection();
}

