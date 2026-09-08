"""Fragment 26_generate_screenshots_gallery_page.py. Loaded into the main module namespace."""
def generate_screenshots_gallery_page(domain: str) -> str:
    """Generate a standalone page for screenshots gallery."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Screenshots Gallery: {domain}</title>
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
.gallery {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
  margin-top: 20px;
}}
.screenshot-card {{
  background: #1e293b;
  border-radius: 8px;
  overflow: hidden;
  transition: transform 0.2s;
}}
.screenshot-card:hover {{
  transform: translateY(-4px);
}}
.screenshot-image {{
  width: 100%;
  height: 200px;
  object-fit: cover;
  cursor: pointer;
  background: #0f172a;
  transition: opacity 0.3s;
}}
.screenshot-image[data-src] {{
  opacity: 0.3;
}}
.screenshot-image.loaded {{
  opacity: 1;
}}
.screenshot-info {{
  padding: 16px;
}}
.screenshot-subdomain {{
  font-weight: 600;
  color: #f1f5f9;
  margin-bottom: 8px;
  word-break: break-all;
}}
.screenshot-url {{
  color: #60a5fa;
  text-decoration: none;
  font-size: 0.85rem;
  word-break: break-all;
}}
.screenshot-url:hover {{
  text-decoration: underline;
}}
.screenshot-meta {{
  margin-top: 8px;
  font-size: 0.8rem;
  color: #94a3b8;
}}
.badge {{
  display: inline-block;
  padding: 2px 8px;
  background: #334155;
  border-radius: 4px;
  font-size: 0.75rem;
  margin-right: 4px;
}}
.status-badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}}
.status-2xx {{ background: #059669; color: white; }}
.status-3xx {{ background: #3b82f6; color: white; }}
.status-4xx {{ background: #f59e0b; color: white; }}
.status-5xx {{ background: #dc2626; color: white; }}
.loading {{
  text-align: center;
  padding: 40px;
  color: #94a3b8;
}}
.empty {{
  text-align: center;
  padding: 60px 20px;
  color: #64748b;
  font-style: italic;
}}
.modal {{
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.9);
  z-index: 1000;
  align-items: center;
  justify-content: center;
  padding: 20px;
}}
.modal.show {{
  display: flex;
}}
.modal img {{
  max-width: 100%;
  max-height: 90vh;
  border-radius: 8px;
}}
.modal-close {{
  position: absolute;
  top: 20px;
  right: 20px;
  color: white;
  font-size: 2rem;
  cursor: pointer;
  background: rgba(0, 0, 0, 0.5);
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
}}
.pagination {{
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin: 30px 0;
  padding: 20px 0;
}}
.pagination button {{
  background: #1e293b;
  color: #e2e8f0;
  border: 1px solid #334155;
  border-radius: 6px;
  padding: 8px 16px;
  cursor: pointer;
  font-size: 0.95rem;
  transition: all 0.2s;
}}
.pagination button:hover:not(:disabled) {{
  background: #334155;
  border-color: #60a5fa;
}}
.pagination button:disabled {{
  opacity: 0.4;
  cursor: not-allowed;
}}
.pagination .page-info {{
  color: #94a3b8;
  font-size: 0.95rem;
  margin: 0 8px;
}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <a href="/" class="back-link">← Back to Dashboard</a>
    <h1 id="gallery-title">Screenshots Gallery</h1>
    <div class="subtitle" id="gallery-subtitle">Loading...</div>
  </div>
  <div class="pagination" id="pagination-top"></div>
  <div id="gallery" class="gallery">
    <div class="loading">Loading screenshots...</div>
  </div>
  <div class="pagination" id="pagination-bottom"></div>
</div>
<div id="modal" class="modal">
  <div class="modal-close" onclick="closeModal()">×</div>
  <img id="modal-image" src="" alt="Screenshot" />
</div>
<script>
const domain = {repr(domain)};
let allScreenshots = [];
let currentPage = 1;
let screenshotsPerPage = 20;

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

function getStatusClass(code) {{
  if (!code) return '';
  if (code >= 200 && code < 300) return 'status-2xx';
  if (code >= 300 && code < 400) return 'status-3xx';
  if (code >= 400 && code < 500) return 'status-4xx';
  if (code >= 500) return 'status-5xx';
  return '';
}}

function openModal(src) {{
  document.getElementById('modal-image').src = src;
  document.getElementById('modal').classList.add('show');
}}

function closeModal() {{
  document.getElementById('modal').classList.remove('show');
}}

document.getElementById('modal').addEventListener('click', (e) => {{
  if (e.target.id === 'modal') closeModal();
}});

async function loadGallery() {{
  try {{
    const resp = await fetch(`/api/gallery/${{encodeURIComponent(domain)}}`);
    if (!resp.ok) throw new Error('Failed to load screenshots');
    const data = await resp.json();
    if (!data.success) throw new Error(data.message || 'Failed to load data');
    
    allScreenshots = data.screenshots;
    document.getElementById('gallery-title').textContent = `Screenshots Gallery: ${{domain}}`;
    document.getElementById('gallery-subtitle').textContent = `${{allScreenshots.length}} screenshots`;
    
    // Load screenshots per page from config if available
    try {{
      const configResp = await fetch('/api/settings');
      if (configResp.ok) {{
        const configData = await configResp.json();
        screenshotsPerPage = configData.config?.screenshots_per_page || 20;
      }}
    }} catch (e) {{
      // Use default if config fails to load
    }}
    
    renderPage();
  }} catch (err) {{
    document.getElementById('gallery').innerHTML = `<div class="empty">Error: ${{escapeHtml(err.message)}}</div>`;
  }}
}}

function renderPage() {{
  if (allScreenshots.length === 0) {{
    document.getElementById('gallery').innerHTML = '<div class="empty">No screenshots available for this domain.</div>';
    document.getElementById('pagination-top').innerHTML = '';
    document.getElementById('pagination-bottom').innerHTML = '';
    return;
  }}
  
  const totalPages = Math.ceil(allScreenshots.length / screenshotsPerPage);
  const startIdx = (currentPage - 1) * screenshotsPerPage;
  const endIdx = Math.min(startIdx + screenshotsPerPage, allScreenshots.length);
  const pageScreenshots = allScreenshots.slice(startIdx, endIdx);
  
  renderGallery(pageScreenshots);
  renderPagination(totalPages, 'pagination-top');
  renderPagination(totalPages, 'pagination-bottom');
}}

function renderPagination(totalPages, elementId) {{
  const paginationEl = document.getElementById(elementId);
  
  if (totalPages <= 1) {{
    paginationEl.innerHTML = '';
    return;
  }}
  
  const startIdx = (currentPage - 1) * screenshotsPerPage;
  const endIdx = Math.min(startIdx + screenshotsPerPage, allScreenshots.length);
  
  paginationEl.innerHTML = `
    <button onclick="goToPage(1)" ${{currentPage === 1 ? 'disabled' : ''}}>«</button>
    <button onclick="goToPage(${{currentPage - 1}})" ${{currentPage === 1 ? 'disabled' : ''}}>‹</button>
    <span class="page-info">Page ${{currentPage}} of ${{totalPages}} (showing ${{startIdx + 1}}-${{endIdx}} of ${{allScreenshots.length}})</span>
    <button onclick="goToPage(${{currentPage + 1}})" ${{currentPage === totalPages ? 'disabled' : ''}}>›</button>
    <button onclick="goToPage(${{totalPages}})" ${{currentPage === totalPages ? 'disabled' : ''}}>»</button>
  `;
}}

function goToPage(page) {{
  const totalPages = Math.ceil(allScreenshots.length / screenshotsPerPage);
  if (page < 1 || page > totalPages) return;
  currentPage = page;
  renderPage();
  window.scrollTo({{ top: 0, behavior: 'smooth' }});
}}

function renderGallery(screenshots) {{
  const html = screenshots.map(shot => {{
    const statusClass = getStatusClass(shot.status_code);
    const statusBadge = shot.status_code ? `<span class="status-badge ${{statusClass}}">${{shot.status_code}}</span>` : '';
    
    return `
      <div class="screenshot-card">
        <img class="screenshot-image" data-src="/screenshots/${{escapeHtml(shot.path)}}" alt="${{escapeHtml(shot.subdomain)}}" onclick="openModal('/screenshots/${{escapeHtml(shot.path)}}')"/>
        <div class="screenshot-info">
          <div class="screenshot-subdomain">${{escapeHtml(shot.subdomain)}}</div>
          <a href="${{escapeHtml(shot.url)}}" target="_blank" class="screenshot-url">${{escapeHtml(shot.url)}}</a>
          <div class="screenshot-meta">
            ${{statusBadge}}
            ${{shot.title ? `<span class="badge">${{escapeHtml(shot.title)}}</span>` : ''}}
            <br>
            <span>Captured: ${{fmtTime(shot.captured_at)}}</span>
          </div>
        </div>
      </div>
    `;
  }}).join('');
  
  document.getElementById('gallery').innerHTML = html;
  
  // Set up lazy loading with Intersection Observer
  const images = document.querySelectorAll('.screenshot-image[data-src]');
  const imageObserver = new IntersectionObserver((entries, observer) => {{
    entries.forEach(entry => {{
      if (entry.isIntersecting) {{
        const img = entry.target;
        img.src = img.getAttribute('data-src');
        img.removeAttribute('data-src');
        img.addEventListener('load', () => {{
          img.classList.add('loaded');
        }});
        observer.unobserve(img);
      }}
    }});
  }}, {{
    rootMargin: '50px'
  }});
  
  images.forEach(img => imageObserver.observe(img));
}}

loadGallery();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Bug bounty agent API: scoped API keys, programs, scope evaluation, findings
# ---------------------------------------------------------------------------

AGENT_API_SCOPES: List[str] = [
    "programs:read",    # list/read programs and their scope
    "programs:write",   # create/update/delete programs
    "scan:run",         # dispatch recon jobs for a program
    "assets:read",      # read discovered hosts/endpoints
    "findings:read",    # read nuclei/nikto/JS findings
    "keys:manage",      # create/revoke API keys
]

# Scopes a non-admin UI session implicitly carries (admins get everything).
AGENT_SESSION_SCOPES: List[str] = [
    "programs:read", "programs:write", "scan:run", "assets:read", "findings:read",
]

AGENT_KEY_PREFIX = "rcc"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1, "unknown": 1}

# Hostname fragments that usually mean "interesting" for a bug bounty agent.
INTERESTING_HOST_KEYWORDS = [
    "admin", "api", "auth", "sso", "oauth", "login", "internal", "intranet", "corp",
    "dev", "test", "qa", "uat", "stage", "staging", "beta", "demo", "sandbox", "preprod",
    "jenkins", "gitlab", "git", "jira", "confluence", "grafana", "kibana", "prometheus",
    "vpn", "mail", "ftp", "backup", "old", "legacy", "deprecated", "portal", "payment",
    "billing", "upload", "files", "s3", "storage", "gateway", "graphql", "gql", "ws",
]
INTERESTING_TECH_KEYWORDS = [
    "jenkins", "wordpress", "drupal", "joomla", "tomcat", "jboss", "weblogic", "struts",
    "grafana", "kibana", "elasticsearch", "phpmyadmin", "gitlab", "jira", "confluence",
    "springboot", "django", "laravel", "rails", "nginx-proxy",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_api_secret(secret: str) -> str:
    """API key secrets are high-entropy random tokens, so a fast digest is enough."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def normalize_agent_scopes(scopes: Any) -> Tuple[List[str], List[str]]:
    """Normalize a requested scope list. Returns (valid_scopes, unknown_scopes)."""
    if isinstance(scopes, str):
        raw = [part for part in re.split(r"[,\s]+", scopes) if part]
    elif isinstance(scopes, (list, tuple, set)):
        raw = [str(part).strip() for part in scopes if str(part).strip()]
    else:
        raw = []
    valid: List[str] = []
    unknown: List[str] = []
    for item in raw:
        item = item.strip().lower()
        if item == "*":
            valid = list(AGENT_API_SCOPES)
            continue
        if item in AGENT_API_SCOPES:
            if item not in valid:
                valid.append(item)
        else:
            unknown.append(item)
    return valid, unknown
