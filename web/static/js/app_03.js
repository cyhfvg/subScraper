// ---- Overview: JS findings ------------------------------------------------
function renderJsFindingsOverview(targets) {
  const container = document.getElementById('overview-js-findings');
  const statSecrets = document.getElementById('stat-js-secrets');
  const statEndpoints = document.getElementById('stat-js-endpoints');
  const entries = Object.entries(targets || {});

  let totalSecrets = 0;
  let totalEndpoints = 0;
  let totalParams = 0;
  let scannedTargets = 0;
  const rows = [];
  const sampleSecrets = [];

  entries.forEach(([domain, info]) => {
    const js = info && info.js_scan;
    if (!js) return;
    const counts = js.summary || {};
    const secrets = Number(counts.secrets || 0);
    const endpoints = Number(counts.endpoints || 0);
    const params = Number(counts.params || 0);
    scannedTargets += 1;
    totalSecrets += secrets;
    totalEndpoints += endpoints;
    totalParams += params;

    const types = js.secret_types || {};
    const typeLabel = Object.keys(types).length
      ? Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 3)
          .map(([name, count]) => `${escapeHtml(name)} &times;${count}`).join(', ')
      : '<span class="muted">none</span>';

    rows.push({
      domain,
      secrets,
      endpoints,
      params,
      files: Number(counts.files || 0),
      scannedAt: js.scanned_at || '',
      typeLabel,
    });

    (js.top_secrets || js.secrets || []).slice(0, 3).forEach(secret => {
      if (!secret) return;
      sampleSecrets.push({
        domain,
        type: secret.type || 'unknown',
        match: secret.match || '',
        source: secret.source || '',
      });
    });
  });

  if (statSecrets) statSecrets.textContent = totalSecrets;
  if (statEndpoints) statEndpoints.textContent = totalEndpoints;
  if (!container) return;

  if (!scannedTargets) {
    container.innerHTML = '<div class="section-placeholder">No JS scan results yet. The JS scan runs as part of the pipeline once hosts are known - enable it under Settings if it is off.</div>';
    return;
  }

  rows.sort((a, b) => b.secrets - a.secrets || a.domain.localeCompare(b.domain));

  const summaryLine = `
    <p class="muted" style="margin-top:0;">
      ${scannedTargets} target(s) scanned &middot;
      <strong>${totalSecrets}</strong> secret(s) &middot;
      <strong>${totalEndpoints}</strong> endpoint(s) &middot;
      <strong>${totalParams}</strong> parameter(s)
    </p>
  `;

  const table = `
    <div class="table-wrapper">
      <table class="targets-table" id="overview-js-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Secrets</th>
            <th>Endpoints</th>
            <th>Params</th>
            <th>JS files</th>
            <th>Top secret types</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(row => `
            <tr>
              <td><a href="/domain/${encodeURIComponent(row.domain)}" class="link-btn">${escapeHtml(row.domain)}</a></td>
              <td>${row.secrets ? `<span class="badge severity-high">${row.secrets}</span>` : '0'}</td>
              <td>${row.endpoints}</td>
              <td>${row.params}</td>
              <td>${row.files}</td>
              <td>${row.typeLabel}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;

  const secretsList = sampleSecrets.length ? `
    <h4 style="margin: 16px 0 8px;">Sample secrets (values redacted)</h4>
    <div class="table-wrapper">
      <table class="monitor-entry-table">
        <thead><tr><th>Domain</th><th>Type</th><th>Value</th><th>Found in</th></tr></thead>
        <tbody>
          ${sampleSecrets.slice(0, 10).map(secret => `
            <tr>
              <td>${escapeHtml(secret.domain)}</td>
              <td>${escapeHtml(secret.type)}</td>
              <td><code>${escapeHtml(secret.match)}</code></td>
              <td class="muted" style="word-break: break-all;">${escapeHtml(secret.source)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  ` : '';

  container.innerHTML = summaryLine + table + secretsList;
}

// ---- How to use this tool: live tool status -------------------------------
let howtoToolsLoaded = false;

function renderHowtoTools(data) {
  const platformEl = document.getElementById('howto-platform');
  const toolsEl = document.getElementById('howto-tools');
  if (!toolsEl) return;

  const platform = (data && data.platform) || {};
  const managers = (data && data.package_managers) || [];
  if (platformEl) {
    const bits = [];
    bits.push(`<strong>${escapeHtml(platform.system_label || 'unknown')}</strong>`);
    if (platform.distro) bits.push(escapeHtml(platform.distro));
    if (platform.arch) bits.push(escapeHtml(platform.arch));
    bits.push(`package managers: ${managers.length ? managers.map(escapeHtml).join(', ') : 'none detected'}`);
    if (platform.system !== 'windows') {
      bits.push(platform.is_root ? 'running as root'
        : (platform.sudo === 'passwordless' ? 'passwordless sudo available'
          : 'no passwordless sudo - system packages must be installed manually'));
    }
    platformEl.innerHTML = bits.join(' &middot; ');
  }

  const tools = (data && data.tools) || [];
  const missing = tools.filter(tool => !tool.installed);
  const installBtn = document.getElementById('howto-install-missing');
  if (installBtn) {
    const autoInstallable = missing.filter(tool => tool.auto_installable);
    installBtn.disabled = autoInstallable.length === 0;
    installBtn.textContent = autoInstallable.length
      ? `Install ${autoInstallable.length} missing tool(s)`
      : (missing.length ? 'Nothing can be installed unattended' : 'All tools installed');
  }

  toolsEl.innerHTML = `
    <p class="muted">${data.installed_count} of ${data.total_count} tools available.</p>
    <div class="table-wrapper">
      <table class="monitor-entry-table">
        <thead><tr><th>Tool</th><th>Status</th><th>Install on this machine</th></tr></thead>
        <tbody>
          ${tools.map(tool => {
            const status = tool.installed
              ? `<span class="badge complete">ready</span><br><span class="muted" style="word-break: break-all;">${escapeHtml(tool.path || '')}</span>`
              : '<span class="badge pending">missing</span>';
            let action = '<span class="muted">-</span>';
            if (!tool.installed) {
              const usable = (tool.install_plan || []).filter(step => step.manager_present && step.package_available);
              const others = (tool.install_plan || []).filter(step => !(step.manager_present && step.package_available));
              const lines = usable.map(step =>
                `<div><code>${escapeHtml(step.display_command)}</code>${step.can_run_unattended ? '' : ` <span class="muted">(${escapeHtml(step.blocked_reason)})</span>`}</div>`);
              if (!lines.length) {
                lines.push(...others.slice(0, 2).map(step =>
                  `<div class="muted"><code>${escapeHtml(step.display_command)}</code> &mdash; ${escapeHtml(step.blocked_reason || 'not available here')}</div>`));
              }
              if (!lines.length) {
                lines.push(`<div class="muted">No packaged install for this OS. See <a href="${escapeHtml(tool.docs || '#')}" target="_blank" rel="noopener">docs</a>.</div>`);
              }
              action = lines.join('');
            }
            const note = tool.note ? `<div class="muted" style="margin-top:4px;">${escapeHtml(tool.note)}</div>` : '';
            return `<tr><td><strong>${escapeHtml(tool.tool)}</strong>${note}</td><td>${status}</td><td>${action}</td></tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;
}

async function loadHowtoTools(force) {
  const toolsEl = document.getElementById('howto-tools');
  if (!toolsEl || (howtoToolsLoaded && !force)) return;
  toolsEl.innerHTML = '<div class="section-placeholder">Checking which tools are installed&hellip;</div>';
  try {
    const resp = await fetch('/api/tools' + (force ? '?refresh=true' : ''));
    const data = await resp.json();
    howtoToolsLoaded = true;
    renderHowtoTools(data);
  } catch (err) {
    toolsEl.innerHTML = '<div class="section-placeholder">Could not read tool status.</div>';
  }
}

function initHowtoView() {
  const refreshBtn = document.getElementById('howto-refresh-tools');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => loadHowtoTools(true));
  }
  const installBtn = document.getElementById('howto-install-missing');
  const statusEl = document.getElementById('howto-install-status');
  if (installBtn) {
    installBtn.addEventListener('click', async () => {
      installBtn.disabled = true;
      if (statusEl) statusEl.textContent = 'Starting install...';
      try {
        const resp = await fetch('/api/tools/install', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        });
        const data = await resp.json();
        if (statusEl) statusEl.textContent = data.message || (data.success ? 'Install started.' : 'Install failed.');
        setTimeout(() => loadHowtoTools(true), 15000);
      } catch (err) {
        if (statusEl) statusEl.textContent = 'Could not start the install.';
        installBtn.disabled = false;
      }
    });
  }
}

function renderOverviewTargets(targets) {
  const entries = Object.entries(targets || {});
  if (!entries.length || !overviewTargetsList) {
    if (overviewTargetsList) {
      overviewTargetsList.innerHTML = '<div class="section-placeholder">No reconnaissance data yet.</div>';
    }
    return;
  }
  
  // Get filter values from localStorage or defaults
  const overviewFilters = getOverviewFilters();
  
  // Apply filters
  const filteredEntries = entries.filter(([domain, info]) => {
    // Domain search filter
    if (overviewFilters.domainSearch && !domain.toLowerCase().includes(overviewFilters.domainSearch.toLowerCase())) {
      return false;
    }
    
    // Status filter (pending/complete)
    if (overviewFilters.status !== 'all') {
      const isPending = info && info.pending;
      if (overviewFilters.status === 'pending' && !isPending) return false;
      if (overviewFilters.status === 'complete' && isPending) return false;
    }
    
    return true;
  });
  
  filteredEntries.sort((a, b) => a[0].localeCompare(b[0]));
  
  // Add filter controls
  const filterControls = `
    <div class="filter-bar" style="margin-bottom: 16px; padding: 12px; background: var(--panel); border-radius: 8px; border: 1px solid #1f2937;">
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Search Domain</label>
          <input type="search" id="overview-domain-search" placeholder="example.com" value="${escapeHtml(overviewFilters.domainSearch || '')}" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
        </div>
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Status</label>
          <select id="overview-status-filter" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
            <option value="all" ${overviewFilters.status === 'all' ? 'selected' : ''}>All</option>
            <option value="pending" ${overviewFilters.status === 'pending' ? 'selected' : ''}>Pending</option>
            <option value="complete" ${overviewFilters.status === 'complete' ? 'selected' : ''}>Complete</option>
          </select>
        </div>
      </div>
      <div style="margin-top: 8px; font-size: 12px; color: var(--muted);">
        Showing ${filteredEntries.length} of ${entries.length} targets
      </div>
    </div>
  `;
  
  const tableRows = filteredEntries.map(([domain, info], idx) => {
    const subs = (info && info.subdomains) || {};
    const subCount = Object.keys(subs).length;
    const isPending = info && info.pending;
    const statusBadge = isPending 
      ? '<span class="badge pending">Pending</span>'
      : '<span class="badge complete">Complete</span>';
    
    // Count findings
    let nucleiCount = 0;
    let niktoCount = 0;
    Object.values(subs).forEach(entry => {
      nucleiCount += Array.isArray(entry.nuclei) ? entry.nuclei.length : 0;
      niktoCount += Array.isArray(entry.nikto) ? entry.nikto.length : 0;
    });
    const findingsCount = nucleiCount + niktoCount;
    
    return `
      <tr>
        <td>${idx + 1}</td>
        <td><a href="/domain/${encodeURIComponent(domain)}" class="link-btn">${escapeHtml(domain)}</a></td>
        <td>${subCount}</td>
        <td>${findingsCount}</td>
        <td>${statusBadge}</td>
      </tr>
    `;
  }).join('');
  
  const table = `
    <div class="table-wrapper">
      <table class="targets-table" id="overview-targets-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Domain</th>
            <th>Subdomains</th>
            <th>Findings</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>${tableRows}</tbody>
      </table>
    </div>
    <div class="table-pagination" id="overview-targets-pagination"></div>
  `;
  
  overviewTargetsList.innerHTML = filterControls + table;
  
  // Attach filter event listeners
  attachOverviewFilterListeners();
  
  // Initialize pagination
  const tableEl = document.getElementById('overview-targets-table');
  const pagerEl = document.getElementById('overview-targets-pagination');
  if (tableEl && pagerEl) {
    initPagination(tableEl, pagerEl, DEFAULT_PAGE_SIZE);
  }
}

function renderTargets(targets) {
  latestTargetsData = targets || {};
  const entries = Object.entries(targets || {});
  statTargets.textContent = entries.length;
  if (!entries.length) {
    targetsList.innerHTML = '<div class="section-placeholder">No reconnaissance data yet.</div>';
    statSubs.textContent = 0;
    return;
  }
  
  // Get filter values from localStorage or defaults
  const targetFilters = getTargetFilters();
  
  // Apply filters
  const filteredEntries = entries.filter(([domain, info]) => {
    // Domain search filter
    if (targetFilters.domainSearch && !domain.toLowerCase().includes(targetFilters.domainSearch.toLowerCase())) {
      return false;
    }
    
    // Status filter (pending/complete)
    if (targetFilters.status !== 'all') {
      const isPending = info && info.pending;
      if (targetFilters.status === 'pending' && !isPending) return false;
      if (targetFilters.status === 'complete' && isPending) return false;
    }
    
    // Has subdomains filter
    if (targetFilters.hasSubdomains) {
      const subs = (info && info.subdomains) || {};
      if (Object.keys(subs).length === 0) return false;
    }
    
    return true;
  });
  
  filteredEntries.sort((a, b) => a[0].localeCompare(b[0]));
  let subCount = 0;
  
  // Add filter controls and export buttons at the top
  const filterControls = `
    <div class="filter-bar" style="margin-bottom: 16px; padding: 16px; background: var(--panel-alt); border-radius: 12px; border: 1px solid #1f2937;">
      <h3 style="margin: 0 0 12px 0; font-size: 14px; color: #93c5fd;">Filter Targets</h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Search Domain</label>
          <input type="search" id="target-domain-search" placeholder="example.com" value="${escapeHtml(targetFilters.domainSearch || '')}" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
        </div>
        <div>
          <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">Status</label>
          <select id="target-status-filter" style="width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #0b152c; color: var(--text);">
            <option value="all" ${targetFilters.status === 'all' ? 'selected' : ''}>All</option>
            <option value="pending" ${targetFilters.status === 'pending' ? 'selected' : ''}>Pending</option>
            <option value="complete" ${targetFilters.status === 'complete' ? 'selected' : ''}>Complete</option>
          </select>
        </div>
        <div style="display: flex; align-items: flex-end;">
          <label style="font-size: 12px; display: flex; align-items: center; gap: 6px; cursor: pointer; padding: 8px 0;">
            <input type="checkbox" id="target-has-subdomains" ${targetFilters.hasSubdomains ? 'checked' : ''}>
            Has Subdomains
          </label>
        </div>
      </div>
      <div style="margin-top: 8px; font-size: 12px; color: var(--muted);">
        Showing ${filteredEntries.length} of ${entries.length} targets
      </div>
    </div>
  `;
  
  const exportButtons = `
    <div class="export-controls" style="margin-bottom: 1rem; display: flex; gap: 0.5rem;">
      <a class="btn secondary small" href="/api/export/state" target="_blank">Export JSON</a>
      <a class="btn secondary small" href="/api/export/csv" target="_blank">Export CSV</a>
    </div>
  `;
  
  const cards = filteredEntries.map(([domain, info]) => {
    const subs = (info && info.subdomains) || {};
    const flags = (info && info.flags) || {};
    const keys = Object.keys(subs).sort();
    
    // Use total_subdomains from backend if available (handles truncation)
    const totalSubdomainCount = info.total_subdomains !== undefined ? info.total_subdomains : keys.length;
    const wasTruncatedByBackend = info.subdomains_truncated || false;
    
    subCount += totalSubdomainCount;
    
    // PERFORMANCE OPTIMIZATION: For domains with many subdomains, only render a preview in the overview
    // This prevents browser freezing when rendering 200k+ subdomains at once
    const hasMany = keys.length > MAX_SUBDOMAINS_PREVIEW;
    const previewKeys = hasMany ? keys.slice(0, MAX_SUBDOMAINS_PREVIEW) : keys;
    const hiddenCount = hasMany ? keys.length - MAX_SUBDOMAINS_PREVIEW : 0;
    
    const rows = previewKeys.map((sub, idx) => {
      const entry = subs[sub] || {};
      const sources = Array.isArray(entry.sources) ? entry.sources.join(', ') : '';
      const httpx = entry.httpx || {};
      const httpSummary = httpx.status_code ? `${httpx.status_code} ${escapeHtml(httpx.title || '')} [${escapeHtml(httpx.webserver || '')}]` : '';
      const screenshot = entry.screenshot || {};
      const screenshotLink = screenshot.path ? `<a href="/screenshots/${escapeHtml(screenshot.path)}" target="_blank">View</a>` : '';
      const nuclei = Array.isArray(entry.nuclei) ? entry.nuclei : [];
      const nucleiBits = nuclei.map(n => `<span class="badge">${escapeHtml((n.severity || '').toUpperCase())}: ${escapeHtml(n.template_id || '')}</span>`).join(' ');
      const nikto = Array.isArray(entry.nikto) ? entry.nikto : [];
      const niktoText = nikto.length ? `${nikto.length} findings` : '';
      const interesting = entry.interesting;
      const borderStyle = interesting === true ? 'border-left: 4px solid #10b981;' : '';
      return `
        <tr style="${borderStyle}">
          <td>${idx + 1}</td>
          <td><a href="/subdomain/${encodeURIComponent(domain)}/${encodeURIComponent(sub)}" class="link-btn">${escapeHtml(sub)}</a></td>
          <td>${escapeHtml(sources)}</td>
          <td>${escapeHtml(httpSummary)}</td>
          <td>${screenshotLink || '—'}</td>
          <td>${nucleiBits}</td>
          <td>${escapeHtml(niktoText)}</td>
        </tr>
      `;
    }).join('');
    
    const badges = `
      <span class="badge">Hosts: ${totalSubdomainCount}</span>
      <span class="badge">DNSx: ${flags.dnsx_done ? 'done' : 'pending'}</span>
      <span class="badge">Ports: ${flags.port_scan_done ? 'done' : 'pending'}</span>
      <span class="badge">httpx: ${flags.httpx_done ? 'done' : 'pending'}</span>
      <span class="badge">vhost: ${flags.vhost_enum_done ? 'done' : 'pending'}</span>
      <span class="badge">Screenshots: ${flags.screenshots_done ? 'done' : 'pending'}</span>
      <span class="badge">nuclei: ${flags.nuclei_done ? 'done' : 'pending'}</span>
      <span class="badge">nikto: ${flags.nikto_done ? 'done' : 'pending'}</span>
    `;
    
    const tableId = `targets-table-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    const paginationId = `targets-pagination-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    
    // Show preview notice if subdomains were limited (either by backend or frontend)
    const previewNotice = (wasTruncatedByBackend || hasMany) ? `
      <div style="padding: 12px; margin-bottom: 8px; background: #1e293b; border-radius: 8px; border: 1px solid #334155;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div>
            <span style="color: #f59e0b;">⚠️</span>
            <span style="color: var(--muted); font-size: 14px;">
              ${wasTruncatedByBackend 
                ? `Showing first ${keys.length} of ${totalSubdomainCount} subdomains for performance.`
                : `Showing first ${MAX_SUBDOMAINS_PREVIEW} of ${totalSubdomainCount} subdomains for performance.`
              }
            </span>
          </div>
          <a href="/domain/${encodeURIComponent(domain)}" class="btn small secondary">View All ${totalSubdomainCount}</a>
        </div>
      </div>
    ` : '';
    
    const table = rows ? `
      ${previewNotice}
      <div class="table-wrapper">
        <table class="targets-table" id="${tableId}">
          <thead>
            <tr>
              <th>#</th>
              <th>Subdomain</th>
              <th>Sources</th>
              <th>HTTP</th>
              <th>Screenshot</th>
              <th>Nuclei</th>
              <th>Nikto</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div class="table-pagination" id="${paginationId}"></div>
    ` : '<p class="muted">No subdomains collected yet.</p>';
    
    // Generate node map visualization (only for domains with reasonable subdomain counts)
    const nodeMapId = `node-map-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    const nodeMap = totalSubdomainCount > 0 && totalSubdomainCount <= 1000 ? `
      <div style="margin: 16px 0;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <h4 style="margin: 0; font-size: 14px; color: #93c5fd;">Subdomain Network Map</h4>
          <button class="btn small" onclick="toggleNodeMap('${nodeMapId}')">Toggle Map</button>
        </div>
        <div id="${nodeMapId}" style="display: none;">
          <canvas id="${nodeMapId}-canvas" width="800" height="400" style="width: 100%; height: 400px; background: #050b18; border-radius: 12px; border: 1px solid #1f2937; cursor: pointer;"></canvas>
        </div>
      </div>
    ` : (totalSubdomainCount > 1000 ? `
      <div style="margin: 16px 0; padding: 12px; background: #1e293b; border-radius: 8px; border: 1px solid #334155;">
        <span style="color: var(--muted); font-size: 14px;">
          Network map disabled for ${totalSubdomainCount} subdomains (use domain detail page for visualization).
        </span>
      </div>
    ` : '');
    
    return `
      <div class="target-card" data-domain="${escapeHtml(domain)}">
        <div class="job-summary">
          <div><a href="/domain/${encodeURIComponent(domain)}" class="link-btn" style="font-size: 1.1rem; font-weight: 600;">${escapeHtml(domain)}</a></div>
          <div>${badges}</div>
        </div>
        ${nodeMap}
        ${table}
      </div>
    `;
  });
  statSubs.textContent = subCount;
  targetsList.innerHTML = exportButtons + filterControls + cards.join('');
  
  // Attach filter event listeners
  attachTargetFilterListeners();
  
  // Initialize pagination for each target's table
  filteredEntries.forEach(([domain]) => {
    const tableId = `targets-table-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    const paginationId = `targets-pagination-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    const table = document.getElementById(tableId);
    const pagerEl = document.getElementById(paginationId);
    if (table && pagerEl) {
      initPagination(table, pagerEl, DEFAULT_PAGE_SIZE);
    }
  });
  
  // Initialize node maps
  entries.forEach(([domain, info]) => {
    const nodeMapId = `node-map-${escapeHtml(domain).replace(/[^a-zA-Z0-9]/g, '-')}`;
    initNodeMap(domain, info, nodeMapId);
  });
}

// Node map visualization functions
