"""Fragment 24_generate_domain_detail_page.py. Loaded into the main module namespace."""
def generate_domain_detail_page(domain: str) -> str:
    """Generate a standalone page for domain details."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Domain Detail: {domain}</title>
<style>
body {{
  margin: 0;
  padding: 20px;
  font-family: system-ui, -apple-system, sans-serif;
  background: #0f172a;
  color: #e2e8f0;
  line-height: 1.6;
}}
.container {{
  max-width: 1400px;
  margin: 0 auto;
}}
.header {{
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 2px solid #1e293b;
}}
.back-link {{
  display: inline-block;
  margin-bottom: 12px;
  color: #60a5fa;
  text-decoration: none;
}}
.back-link:hover {{
  text-decoration: underline;
}}
h1 {{
  margin: 0 0 8px 0;
  font-size: 2rem;
  color: #f1f5f9;
}}
.subtitle {{
  color: #94a3b8;
  font-size: 0.95rem;
}}
.stats-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}}
.stat-card {{
  background: #1e293b;
  border-radius: 12px;
  padding: 20px;
  border: 1px solid #334155;
}}
.stat-card .label {{
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #94a3b8;
  margin-bottom: 8px;
}}
.stat-card .value {{
  font-size: 28px;
  font-weight: 700;
  color: #f1f5f9;
}}
.section {{
  background: #1e293b;
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 24px;
  border: 1px solid #334155;
}}
.section h2 {{
  margin: 0 0 16px 0;
  font-size: 1.5rem;
  color: #fbbf24;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 12px;
}}
th, td {{
  padding: 12px;
  text-align: left;
  border-bottom: 1px solid #334155;
}}
th {{
  background: #0f172a;
  color: #94a3b8;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}}
.badge {{
  display: inline-block;
  padding: 4px 12px;
  background: #334155;
  border-radius: 4px;
  font-size: 0.85rem;
  margin: 2px 4px;
}}
.badge.complete {{
  background: #065f46;
  color: #a7f3d0;
}}
.badge.pending {{
  background: #78350f;
  color: #fde68a;
}}
.severity-pill {{
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 600;
  text-transform: uppercase;
}}
.severity-pill.CRITICAL {{ background: #dc2626; color: white; }}
.severity-pill.HIGH {{ background: #ea580c; color: white; }}
.severity-pill.MEDIUM {{ background: #f59e0b; color: white; }}
.severity-pill.LOW {{ background: #eab308; color: #1e293b; }}
.severity-pill.INFO {{ background: #3b82f6; color: white; }}
.muted {{
  color: #64748b;
  font-style: italic;
}}
.loading {{
  text-align: center;
  padding: 40px;
  color: #94a3b8;
}}
.link {{
  color: #60a5fa;
  text-decoration: none;
}}
.link:hover {{
  text-decoration: underline;
}}
.actions {{
  display: flex;
  gap: 12px;
  margin: 16px 0;
}}
.btn {{
  padding: 10px 20px;
  background: #2563eb;
  color: white;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  display: inline-block;
}}
.btn:hover {{
  background: #1d4ed8;
}}
.btn.secondary {{
  background: #475569;
}}
.btn.secondary:hover {{
  background: #334155;
}}
.table-pagination {{
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 16px;
  justify-content: flex-end;
}}
.table-pagination button {{
  padding: 6px 12px;
  background: #1e293b;
  border: 1px solid #334155;
  color: #e2e8f0;
  border-radius: 6px;
  cursor: pointer;
}}
.table-pagination button:disabled {{
  opacity: 0.4;
  cursor: not-allowed;
}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <a href="/" class="back-link">← Back to Dashboard</a>
    <h1 id="domain-title">Loading...</h1>
    <div class="subtitle">Domain Overview</div>
  </div>
  <div id="content">
    <div class="loading">Loading domain details...</div>
  </div>
</div>
<script>
const domain = {repr(domain)};
const DEFAULT_PAGE_SIZE = 50;

function escapeHtml(text) {{
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}}

function fmtTime(iso) {{
  if (!iso) return '—';
  try {{
    const date = new Date(iso);
    return date.toLocaleString();
  }} catch (_) {{
    return iso;
  }}
}}

function initPagination(table, pagerEl, pageSize) {{
  if (!table || !pagerEl) return;
  const state = {{
    table,
    pagerEl,
    pageSize: pageSize || DEFAULT_PAGE_SIZE,
    currentPage: 1,
    totalPages: 1,
  }};
  
  pagerEl.addEventListener('click', (event) => {{
    const btn = event.target.closest('[data-page-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-page-action');
    if (action === 'prev') {{
      state.currentPage = Math.max(1, state.currentPage - 1);
    }} else if (action === 'next') {{
      state.currentPage = Math.min(state.totalPages, state.currentPage + 1);
    }} else if (action === 'first') {{
      state.currentPage = 1;
    }} else if (action === 'last') {{
      state.currentPage = state.totalPages;
    }}
    refreshPagination(table, state, pagerEl);
  }});
  
  table._paginationState = state;
  refreshPagination(table, state, pagerEl);
}}

function refreshPagination(table, state, pagerEl) {{
  const rows = Array.from(table.tBodies[0] ? table.tBodies[0].rows : []);
  let visibleCount = rows.length;
  
  state.totalPages = Math.max(1, Math.ceil(visibleCount / state.pageSize));
  if (state.currentPage > state.totalPages) {{
    state.currentPage = state.totalPages;
  }}
  
  const start = (state.currentPage - 1) * state.pageSize;
  const end = start + state.pageSize;
  
  rows.forEach((row, idx) => {{
    row.style.display = (idx >= start && idx < end) ? '' : 'none';
  }});
  
  if (state.totalPages <= 1) {{
    pagerEl.innerHTML = '';
    return;
  }}
  
  pagerEl.innerHTML = `
    <span style="color: #94a3b8; margin-right: auto;">${{visibleCount}} rows</span>
    <button data-page-action="first" ${{state.currentPage === 1 ? 'disabled' : ''}}>&laquo;</button>
    <button data-page-action="prev" ${{state.currentPage === 1 ? 'disabled' : ''}}>&lsaquo;</button>
    <span>Page ${{state.currentPage}} / ${{state.totalPages}}</span>
    <button data-page-action="next" ${{state.currentPage === state.totalPages ? 'disabled' : ''}}>&rsaquo;</button>
    <button data-page-action="last" ${{state.currentPage === state.totalPages ? 'disabled' : ''}}>&raquo;</button>
  `;
}}

async function loadDomainDetail() {{
  try {{
    const resp = await fetch(`/api/domain/${{encodeURIComponent(domain)}}`);
    if (!resp.ok) throw new Error('Failed to load domain data');
    const data = await resp.json();
    if (!data.success) throw new Error(data.message || 'Failed to load data');
    
    document.getElementById('domain-title').textContent = domain;
    renderDomainDetail(data.data);
  }} catch (err) {{
    document.getElementById('content').innerHTML = `<div class="section"><p class="muted">Error: ${{escapeHtml(err.message)}}</p></div>`;
  }}
}}

function renderDomainDetail(info) {{
  const subdomains = info.subdomains || {{}};
  const flags = info.flags || {{}};
  const subKeys = Object.keys(subdomains);
  
  // Calculate stats
  let httpCount = 0;
  let nucleiCount = 0;
  let niktoCount = 0;
  let screenshotCount = 0;
  let maxSeverity = 'NONE';
  
  const severityOrder = ['NONE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  
  subKeys.forEach(sub => {{
    const entry = subdomains[sub];
    if (entry.httpx) httpCount++;
    if (entry.screenshot) screenshotCount++;
    const nuclei = entry.nuclei || [];
    nucleiCount += nuclei.length;
    nuclei.forEach(finding => {{
      const sev = (finding.severity || 'INFO').toUpperCase();
      if (severityOrder.indexOf(sev) > severityOrder.indexOf(maxSeverity)) {{
        maxSeverity = sev;
      }}
    }});
    const nikto = entry.nikto || [];
    niktoCount += nikto.length;
    nikto.forEach(finding => {{
      const sev = (finding.severity || finding.risk || 'INFO').toUpperCase();
      if (severityOrder.indexOf(sev) > severityOrder.indexOf(maxSeverity)) {{
        maxSeverity = sev;
      }}
    }});
  }});
  
  const completedSteps = Object.values(flags).filter(Boolean).length;
  const totalSteps = Object.keys(flags).length;
  const progress = totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0;
  
  let html = `
    <div class="stats-grid">
      <div class="stat-card">
        <div class="label">Subdomains</div>
        <div class="value">${{subKeys.length}}</div>
      </div>
      <div class="stat-card">
        <div class="label">HTTP Responses</div>
        <div class="value">${{httpCount}}</div>
      </div>
      <div class="stat-card">
        <div class="label">Screenshots</div>
        <div class="value">${{screenshotCount}}</div>
      </div>
      <div class="stat-card">
        <div class="label">Nuclei Findings</div>
        <div class="value">${{nucleiCount}}</div>
      </div>
      <div class="stat-card">
        <div class="label">Nikto Findings</div>
        <div class="value">${{niktoCount}}</div>
      </div>
      <div class="stat-card">
        <div class="label">Max Severity</div>
        <div class="value"><span class="severity-pill ${{maxSeverity}}">${{maxSeverity}}</span></div>
      </div>
      <div class="stat-card">
        <div class="label">Progress</div>
        <div class="value">${{progress}}%</div>
      </div>
    </div>
    
    <div class="actions">
      <a href="/gallery/${{encodeURIComponent(domain)}}" class="btn">View Screenshots Gallery</a>
      <a href="/#reports" class="btn secondary" onclick="window.parent.postMessage({{type:'selectReport',domain:domain}}, '*')">View Full Report</a>
    </div>
    
    <div class="section">
      <h2>Scan Progress</h2>
      <table>
        <thead>
          <tr>
            <th>Tool</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  const flagLabels = {{
    amass_done: 'Amass',
    subfinder_done: 'Subfinder',
    assetfinder_done: 'Assetfinder',
    findomain_done: 'Findomain',
    sublist3r_done: 'Sublist3r',
    crtsh_done: 'crt.sh',
    github_subdomains_done: 'GitHub Subdomains',
    dnsx_done: 'DNSx',
    ffuf_done: 'ffuf',
    httpx_done: 'httpx',
    waybackurls_done: 'Wayback URLs',
    gau_done: 'GAU',
    screenshots_done: 'Screenshots',
    nuclei_done: 'Nuclei',
    nikto_done: 'Nikto'
  }};
  
  Object.entries(flagLabels).forEach(([flag, label]) => {{
    const status = flags[flag] ? 'complete' : 'pending';
    html += `
      <tr>
        <td>${{label}}</td>
        <td><span class="badge ${{status}}">${{status === 'complete' ? '✅ Complete' : '⏳ Pending'}}</span></td>
      </tr>
    `;
  }});
  
  html += `
        </tbody>
      </table>
    </div>
    
    <div class="section">
      <h2>Subdomains (${{subKeys.length}})</h2>
      <table id="subdomains-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Subdomain</th>
            <th>Status</th>
            <th>HTTP Status</th>
            <th>Title</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  subKeys.forEach((sub, idx) => {{
    const entry = subdomains[sub];
    const httpx = entry.httpx || {{}};
    const nuclei = entry.nuclei || [];
    const nikto = entry.nikto || [];
    const findings = nuclei.length + nikto.length;
    const interesting = entry.interesting;
    
    let interestingBadge = '';
    if (interesting === true) {{
      interestingBadge = '<span class="badge" style="background: #10b981; color: white;">⭐ Interesting</span>';
    }} else if (interesting === false) {{
      interestingBadge = '<span class="badge" style="background: #ef4444; color: white;">🚫 Not Interesting</span>';
    }}
    
    const borderStyle = interesting === true ? 'border-left: 4px solid #10b981;' : '';
    
    html += `
      <tr style="${{borderStyle}}">
        <td>${{idx + 1}}</td>
        <td><a href="/subdomain/${{encodeURIComponent(domain)}}/${{encodeURIComponent(sub)}}" class="link">${{escapeHtml(sub)}}</a></td>
        <td>${{interestingBadge}}</td>
        <td>${{httpx.status_code || '—'}}</td>
        <td>${{escapeHtml(httpx.title || '—')}}</td>
        <td>${{findings > 0 ? findings + ' findings' : '—'}}</td>
      </tr>
    `;
  }});
  
  html += `
        </tbody>
      </table>
      <div class="table-pagination" id="subdomains-pagination"></div>
    </div>
  `;
  
  document.getElementById('content').innerHTML = html;
  
  // Initialize pagination
  const table = document.getElementById('subdomains-table');
  const pagerEl = document.getElementById('subdomains-pagination');
  if (table && pagerEl) {{
    initPagination(table, pagerEl, DEFAULT_PAGE_SIZE);
  }}
}}

loadDomainDetail();
</script>
</body>
</html>
"""
