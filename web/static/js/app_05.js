function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatNumber(num) {
  return num.toString().replace(/\\B(?=(\\d{3})+(?!\\d))/g, ",");
}

async function fetchSystemResources() {
  try {
    const resp = await fetch('/api/system-resources');
    if (!resp.ok) throw new Error('Failed to fetch system resources');
    const data = await resp.json();
    renderSystemResources(data);
  } catch (err) {
    const resourcesBody = document.getElementById('resources-body');
    if (resourcesBody) {
      resourcesBody.innerHTML = `<div class="section-placeholder">Error: ${escapeHtml(err.message)}</div>`;
    }
  }
}

function closeDetailModal() {
  detailOverlay.classList.remove('show');
  detailContent.innerHTML = '';
}

async function openSubdomainDetail(domain, sub) {
  if (!latestTargetsData[domain] || !latestTargetsData[domain].subdomains[sub]) return;
  const info = latestTargetsData[domain].subdomains[sub];
  const history = await fetchHistory(domain);
  detailContent.innerHTML = buildDetailHtml(domain, sub, info, history);
  detailOverlay.classList.add('show');
}

async function fetchHistory(domain) {
  if (historyCache[domain]) return historyCache[domain];
  try {
    const resp = await fetch(`/api/history?domain=${encodeURIComponent(domain)}`);
    if (!resp.ok) throw new Error('Failed to fetch history');
    const data = await resp.json();
    historyCache[domain] = data.events || [];
    return historyCache[domain];
  } catch (err) {
    return [];
  }
}

function buildDetailHtml(domain, sub, info, history) {
  const sources = info.sources || [];
  const httpx = info.httpx || {};
  const screenshot = info.screenshot || {};
  const nuclei = info.nuclei || [];
  const nikto = info.nikto || [];
  const filteredHistory = history.filter(event => {
    const text = (event.text || '').toLowerCase();
    const src = (event.source || '').toLowerCase();
    const needle = (sub || '').toLowerCase();
    return needle && (text.includes(needle) || src.includes(needle));
  });
  
  // Metadata section
  const metadataHtml = `
    <div class="detail-section">
      <h4>Metadata</h4>
      <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px;">
        <div>
          <strong>Parent Domain:</strong><br>
          <span class="badge">${escapeHtml(domain)}</span>
        </div>
        <div>
          <strong>Discovery Sources:</strong><br>
          ${sources.length ? sources.map(s => `<span class="badge">${escapeHtml(s)}</span>`).join(' ') : '<span class="muted">Unknown</span>'}
        </div>
      </div>
    </div>
  `;
  
  // HTTP section - full details
  const httpHtml = `
    <div class="detail-section">
      <h4>HTTP Response</h4>
      ${Object.keys(httpx).length ? `
        <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px;">
          <div><strong>URL:</strong><br>${escapeHtml(httpx.url || '—')}</div>
          <div><strong>Status Code:</strong><br>${httpx.status_code || '—'}</div>
          <div><strong>Title:</strong><br>${escapeHtml(httpx.title || '—')}</div>
          <div><strong>Server:</strong><br>${escapeHtml(httpx.webserver || httpx.server || '—')}</div>
          <div><strong>Content-Type:</strong><br>${escapeHtml(httpx.content_type || '—')}</div>
          <div><strong>Tech Stack:</strong><br>${escapeHtml((httpx.tech || httpx.technologies || []).join(', ') || '—')}</div>
        </div>
      ` : '<p class="muted">No HTTP data available</p>'}
    </div>
  `;
  
  // Screenshot section - inline display
  const screenshotHtml = `
    <div class="detail-section">
      <h4>Screenshot</h4>
      ${screenshot.path ? `
        <div style="margin-top:8px;">
          <img src="/screenshots/${escapeHtml(screenshot.path)}" style="max-width:100%; border-radius:8px; border:1px solid #1f2937;" alt="Screenshot of ${escapeHtml(sub)}" />
          ${screenshot.captured_at ? `<p class="muted" style="margin-top:8px;">Captured ${fmtTime(screenshot.captured_at)}</p>` : ''}
        </div>
      ` : '<p class="muted">No screenshot available</p>'}
    </div>
  `;
  
  // URLs section - placeholder for future implementation
  const urlsHtml = `
    <div class="detail-section">
      <h4>Discovered URLs</h4>
      <p class="muted">URL discovery from Waybackurls and GAU is performed at the domain level. Per-subdomain URL tracking coming soon.</p>
    </div>
  `;
  
  // Nuclei section - detailed findings table
  let nucleiHtml = '<div class="detail-section"><h4>Nuclei Findings</h4>';
  if (nuclei.length) {
    nucleiHtml += `
      <div class="table-wrapper">
        <table class="targets-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Template</th>
              <th>Name</th>
              <th>Matched At</th>
            </tr>
          </thead>
          <tbody>
            ${nuclei.map(finding => {
              const severity = normalizeSeverity(finding.severity, 'INFO');
              const templateId = finding.template_id || finding['template-id'] || 'N/A';
              const name = finding.name || '';
              const matchedAt = finding.matched_at || finding['matched-at'] || finding.url || '';
              return `
                <tr>
                  <td><span class="severity-pill ${escapeHtml(severity)}">${escapeHtml(severity)}</span></td>
                  <td>${escapeHtml(templateId)}</td>
                  <td>${escapeHtml(name)}</td>
                  <td>${escapeHtml(matchedAt)}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  } else {
    nucleiHtml += '<p class="muted">No Nuclei findings</p>';
  }
  nucleiHtml += '</div>';
  
  // Nikto section - detailed findings table
  let niktoHtml = '<div class="detail-section"><h4>Nikto Findings</h4>';
  if (nikto.length) {
    niktoHtml += `
      <div class="table-wrapper">
        <table class="targets-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Message</th>
              <th>Reference</th>
            </tr>
          </thead>
          <tbody>
            ${nikto.map(finding => {
              const severity = normalizeSeverity(finding.severity || finding.risk, 'INFO');
              const message = finding.msg || finding.description || finding.raw || '';
              const reference = finding.uri || (finding.osvdb ? `OSVDB-${finding.osvdb}` : '') || '—';
              return `
                <tr>
                  <td><span class="severity-pill ${escapeHtml(severity)}">${escapeHtml(severity)}</span></td>
                  <td>${escapeHtml(message)}</td>
                  <td>${escapeHtml(reference)}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  } else {
    niktoHtml += '<p class="muted">No Nikto findings</p>';
  }
  niktoHtml += '</div>';
  
  // Timeline section
  const timelineHtml = `
    <div class="detail-section">
      <h4>Timeline (Filtered Events)</h4>
      <div class="timeline">
        ${filteredHistory.length ? filteredHistory.map(evt => `
          <div class="timeline-entry">
            <div class="meta">${escapeHtml(evt.ts || '')} — ${escapeHtml(evt.source || '')}</div>
            <div>${escapeHtml(evt.text || '')}</div>
          </div>
        `).join('') : '<p class="muted">No history for this subdomain yet.</p>'}
      </div>
    </div>
  `;
  
  return `
    <h3>${escapeHtml(sub)} <span class="badge">${escapeHtml(domain)}</span></h3>
    ${metadataHtml}
    ${httpHtml}
    ${screenshotHtml}
    ${urlsHtml}
    ${nucleiHtml}
    ${niktoHtml}
    ${timelineHtml}
  `;
}

function computeReportStats(info) {
  const subs = Object.values(info && info.subdomains || {});
  let httpCount = 0;
  let nucleiCount = 0;
  let niktoCount = 0;
  let screenshotCount = 0;
  let maxSeverity = 'NONE';
  let maxNucleiSeverity = 'NONE';
  let maxNiktoSeverity = 'NONE';
  let processedSubdomains = 0;
  let pendingSubdomains = 0;
  let pendingHttp = 0;
  let pendingScreenshots = 0;
  let pendingNuclei = 0;
  let pendingNikto = 0;
  const cfg = latestConfig || {};
  const enableScreenshots = cfg.enable_screenshots !== false;
  const skipNiktoDefault = !!cfg.skip_nikto_by_default;
  const options = info && info.options || {};
  const skipNikto = options.skip_nikto !== undefined ? !!options.skip_nikto : skipNiktoDefault;
  subs.forEach(entry => {
    const scans = entry && entry.scans || {};
    const httpDone = !!(entry && entry.httpx) || !!scans.httpx;
    const screenshotDone = !enableScreenshots || !!(entry && entry.screenshot) || !!scans.screenshots;
    const nucleiDone = !!scans.nuclei;
    const niktoRequired = !skipNikto;
    const niktoDone = !niktoRequired || !!scans.nikto;
    if (entry && entry.httpx) httpCount += 1;
    nucleiCount += Array.isArray(entry && entry.nuclei) ? entry.nuclei.length : 0;
    niktoCount += Array.isArray(entry && entry.nikto) ? entry.nikto.length : 0;
    if (entry && entry.screenshot) screenshotCount += 1;
    if (!httpDone) pendingHttp += 1;
    if (enableScreenshots && !screenshotDone) pendingScreenshots += 1;
    if (!nucleiDone) pendingNuclei += 1;
    if (niktoRequired && !niktoDone) pendingNikto += 1;
    if (httpDone && screenshotDone && nucleiDone && niktoDone) {
      processedSubdomains += 1;
    } else {
      pendingSubdomains += 1;
    }
    (entry && entry.nuclei || []).forEach(finding => {
      const sev = normalizeSeverity(finding && finding.severity, 'INFO');
      if (severityIsHigher(sev, maxSeverity)) {
        maxSeverity = sev;
      }
      if (severityIsHigher(sev, maxNucleiSeverity)) {
        maxNucleiSeverity = sev;
      }
    });
    (entry && entry.nikto || []).forEach(finding => {
      const sev = normalizeSeverity(finding && finding.severity, 'INFO');
      if (severityIsHigher(sev, maxSeverity)) {
        maxSeverity = sev;
      }
      if (severityIsHigher(sev, maxNiktoSeverity)) {
        maxNiktoSeverity = sev;
      }
    });
  });
  return {
    subdomains: subs.length,
    http: httpCount,
    nuclei: nucleiCount,
    nikto: niktoCount,
    screenshots: screenshotCount,
    maxSeverity,
    maxNucleiSeverity,
    maxNiktoSeverity,
    processed_subdomains: processedSubdomains,
    pending_subdomains: pendingSubdomains,
    pending_http: pendingHttp,
    pending_screenshots: pendingScreenshots,
    pending_nuclei: pendingNuclei,
    pending_nikto: pendingNikto,
    progress: subs.length ? Math.min(100, Math.round((processedSubdomains / subs.length) * 100)) : (info && info.flags && Object.values(info.flags).every(Boolean) ? 100 : 0),
  };
}

function hasActiveJob(domain) {
  if (!domain) return false;
  return latestRunningJobs.some(job => job.domain === domain) ||
    latestQueuedJobs.some(job => job.domain === domain);
}

// Report filter management
function getReportFilters() {
  try {
    const saved = localStorage.getItem('reportFilters');
    return saved ? JSON.parse(saved) : {
      domainSearch: '',
      status: 'all',
      maxSeverity: 'all',
      hasFindings: false,
      hasScreenshots: false
    };
  } catch (e) {
    return {
      domainSearch: '',
      status: 'all',
      maxSeverity: 'all',
      hasFindings: false,
      hasScreenshots: false
    };
  }
}

function buildExportURLWithFilters(baseUrl) {
  const filters = getReportFilters();
  const params = new URLSearchParams();
  
  if (filters.domainSearch) params.set('domainSearch', filters.domainSearch);
  if (filters.status !== 'all') params.set('status', filters.status);
  if (filters.maxSeverity !== 'all') params.set('maxSeverity', filters.maxSeverity);
  if (filters.hasFindings) params.set('hasFindings', 'true');
  if (filters.hasScreenshots) params.set('hasScreenshots', 'true');
  
  const queryString = params.toString();
  return queryString ? `${baseUrl}?${queryString}` : baseUrl;
}

function saveReportFiltersToStorage() {
  try {
    const domainSearch = document.getElementById('report-domain-search')?.value || '';
    const status = document.getElementById('report-status-filter')?.value || 'all';
    const maxSeverity = document.getElementById('report-severity-filter')?.value || 'all';
    const hasFindings = document.getElementById('report-has-findings')?.checked || false;
    const hasScreenshots = document.getElementById('report-has-screenshots')?.checked || false;
    
    localStorage.setItem('reportFilters', JSON.stringify({
      domainSearch,
      status,
      maxSeverity,
      hasFindings,
      hasScreenshots
    }));
  } catch (e) {
    // Ignore localStorage errors
  }
}

function attachReportFilterListeners() {
  const domainSearch = document.getElementById('report-domain-search');
  const statusFilter = document.getElementById('report-status-filter');
  const severityFilter = document.getElementById('report-severity-filter');
  const findingsFilter = document.getElementById('report-has-findings');
  const screenshotsFilter = document.getElementById('report-has-screenshots');
  
  const applyFilters = () => {
    saveReportFiltersToStorage();
    renderReports(latestTargetsData);
  };

  if (domainSearch) {
    let domainSearchTimer = null;
    domainSearch.addEventListener('input', () => {
      clearTimeout(domainSearchTimer);
      domainSearchTimer = setTimeout(() => {
        const caret = domainSearch.selectionStart;
        applyFilters();
        // Re-render recreates the input; restore focus + caret
        const next = document.getElementById('report-domain-search');
        if (next) {
          next.focus();
          try { next.setSelectionRange(caret, caret); } catch (e) {}
        }
      }, 350);
    });
  }
  if (statusFilter) {
    statusFilter.addEventListener('change', applyFilters);
  }
  if (severityFilter) {
    severityFilter.addEventListener('change', applyFilters);
  }
  if (findingsFilter) {
    findingsFilter.addEventListener('change', applyFilters);
  }
  if (screenshotsFilter) {
    screenshotsFilter.addEventListener('change', applyFilters);
  }
}

// Target filter management
function getTargetFilters() {
  try {
    const saved = localStorage.getItem('targetFilters');
    return saved ? JSON.parse(saved) : {
      domainSearch: '',
      status: 'all',
      hasSubdomains: false
    };
  } catch (e) {
    return {
      domainSearch: '',
      status: 'all',
      hasSubdomains: false
    };
  }
}

function saveTargetFiltersToStorage() {
  try {
    const domainSearch = document.getElementById('target-domain-search')?.value || '';
    const status = document.getElementById('target-status-filter')?.value || 'all';
    const hasSubdomains = document.getElementById('target-has-subdomains')?.checked || false;
    
    localStorage.setItem('targetFilters', JSON.stringify({
      domainSearch,
      status,
      hasSubdomains
    }));
  } catch (e) {
    // Ignore localStorage errors
  }
}

function attachTargetFilterListeners() {
  const domainSearch = document.getElementById('target-domain-search');
  const statusFilter = document.getElementById('target-status-filter');
  const subdomainsFilter = document.getElementById('target-has-subdomains');
  
  const applyFilters = () => {
    saveTargetFiltersToStorage();
    renderTargets(latestTargetsData);
  };
  
  if (domainSearch) {
    domainSearch.addEventListener('input', applyFilters);
  }
  if (statusFilter) {
    statusFilter.addEventListener('change', applyFilters);
  }
  if (subdomainsFilter) {
    subdomainsFilter.addEventListener('change', applyFilters);
  }
}

// Overview filter management
