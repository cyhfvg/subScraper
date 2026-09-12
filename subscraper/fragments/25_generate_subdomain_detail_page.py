"""Fragment 25_generate_subdomain_detail_page.py. Loaded into the main module namespace."""
def generate_subdomain_detail_page(domain: str, subdomain: str) -> str:
    """Generate a standalone page for subdomain details."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Subdomain Detail: {subdomain}</title>
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
  max-width: 1200px;
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
.section {{
  background: #1e293b;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
}}
.section h2 {{
  margin: 0 0 16px 0;
  font-size: 1.25rem;
  color: #f1f5f9;
}}
.grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}}
.field {{
  padding: 12px;
  background: #0f172a;
  border-radius: 6px;
}}
.field strong {{
  display: block;
  color: #94a3b8;
  font-size: 0.85rem;
  margin-bottom: 4px;
}}
.field-value {{
  color: #e2e8f0;
  word-break: break-word;
}}
.badge {{
  display: inline-block;
  padding: 4px 8px;
  background: #334155;
  border-radius: 4px;
  font-size: 0.85rem;
  margin: 2px;
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
}}
img {{
  max-width: 100%;
  border-radius: 8px;
  border: 1px solid #334155;
}}
.muted {{
  color: #64748b;
  font-style: italic;
}}
.loading {{
  text-align: center;
  padding: 40px;
  color: #94a3b8;
}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <a href="/" class="back-link">← Back to Dashboard</a>
    <h1 id="subdomain-title">Loading...</h1>
    <div class="subtitle">Subdomain Details</div>
  </div>
  <div id="content">
    <div class="loading">Loading subdomain details...</div>
  </div>
</div>
<script>
const domain = {repr(domain)};
const subdomain = {repr(subdomain)};

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

async function loadSubdomainDetail() {{
  try {{
    const resp = await fetch(`/api/subdomain/${{encodeURIComponent(domain)}}/${{encodeURIComponent(subdomain)}}`);
    if (!resp.ok) throw new Error('Failed to load subdomain data');
    const data = await resp.json();
    if (!data.success) throw new Error(data.message || 'Failed to load data');
    
    document.getElementById('subdomain-title').textContent = subdomain;
    renderSubdomainDetail(data.data, data.history, data.endpoints, data.flags);
  }} catch (err) {{
    document.getElementById('content').innerHTML = `<div class="section"><p class="muted">Error: ${{escapeHtml(err.message)}}</p></div>`;
  }}
}}

function renderSubdomainDetail(info, history, endpoints, flags) {{
  const sources = info.sources || [];
  const httpx = info.httpx || {{}};
  const screenshot = info.screenshot || {{}};
  const nuclei = info.nuclei || [];
  const nikto = info.nikto || [];
  const interesting = info.interesting;
  const comments = info.comments || [];
  
  const ffufDone = flags?.vhost_enum_done || flags?.ffuf_done || false;

  
  let html = '';
  
  // Marking and action buttons
  html += `
    <div class="section">
      <h2>Actions</h2>
      <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 16px; flex-wrap: wrap;">
        <button class="btn" onclick="markSubdomain(true)" style="background: #10b981;">Mark as Interesting</button>
        <button class="btn" onclick="markSubdomain(false)" style="background: #ef4444;">Mark as Not Interesting</button>
        <button class="btn secondary" onclick="markSubdomain(null)">Clear Mark</button>
        ${{interesting === true ? '<span class="badge" style="background: #10b981; color: white; margin-left: 8px;">⭐ Interesting</span>' : ''}}
        ${{interesting === false ? '<span class="badge" style="background: #ef4444; color: white; margin-left: 8px;">🚫 Not Interesting</span>' : ''}}
      </div>
      <div style="display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap;">
        <button class="btn" onclick="runContentDiscovery('ffuf')" style="background: #f59e0b;">
          Run ffuf vhost ${{ffufDone ? 'done' : ''}}
        </button>
      </div>
      <div id="content-discovery-status" style="margin-top: 12px; padding: 8px; border-radius: 6px; display: none;"></div>
    </div>
  `;
  
  // Metadata section
  html += `
    <div class="section">
      <h2>Metadata</h2>
      <div class="grid">
        <div class="field">
          <strong>Parent Domain</strong>
          <div class="field-value"><span class="badge">${{escapeHtml(domain)}}</span></div>
        </div>
        <div class="field">
          <strong>Discovery Sources</strong>
          <div class="field-value">${{sources.length ? sources.map(s => `<span class="badge">${{escapeHtml(s)}}</span>`).join(' ') : '<span class="muted">Unknown</span>'}}</div>
        </div>
      </div>
    </div>
  `;
  
  // HTTP section
  html += `
    <div class="section">
      <h2>HTTP Response</h2>
      ${{Object.keys(httpx).length ? `
        <div class="grid">
          <div class="field"><strong>URL</strong><div class="field-value">${{(httpx.url && (httpx.url.startsWith('http://') || httpx.url.startsWith('https://'))) ? `<a href="${{escapeHtml(httpx.url)}}" target="_blank" rel="noopener noreferrer" style="color: #60a5fa; text-decoration: none;">${{escapeHtml(httpx.url)}}</a>` : escapeHtml(httpx.url || '—')}}</div></div>
          <div class="field"><strong>Status Code</strong><div class="field-value">${{httpx.status_code || '—'}}</div></div>
          <div class="field"><strong>Title</strong><div class="field-value">${{escapeHtml(httpx.title || '—')}}</div></div>
          <div class="field"><strong>Server</strong><div class="field-value">${{escapeHtml(httpx.webserver || httpx.server || '—')}}</div></div>
          <div class="field"><strong>Content-Type</strong><div class="field-value">${{escapeHtml(httpx.content_type || '—')}}</div></div>
          <div class="field"><strong>Tech Stack</strong><div class="field-value">${{escapeHtml((httpx.tech || httpx.technologies || []).join(', ') || '—')}}</div></div>
        </div>
      ` : '<p class="muted">No HTTP data available</p>'}}
    </div>
  `;
  
  // Screenshot section
  html += `
    <div class="section">
      <h2>Screenshot</h2>
      ${{screenshot.path ? `
        <div>
          <img src="/screenshots/${{escapeHtml(screenshot.path)}}" alt="Screenshot of ${{escapeHtml(subdomain)}}" />
          ${{screenshot.captured_at ? `<p class="muted" style="margin-top: 12px;">Captured ${{fmtTime(screenshot.captured_at)}}</p>` : ''}}
        </div>
      ` : '<p class="muted">No screenshot available</p>'}}
    </div>
  `;
  
  // Nuclei section
  html += `<div class="section"><h2>Nuclei Findings (${{nuclei.length}})</h2>`;
  if (nuclei.length) {{
    html += `
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Template</th>
            <th>Name</th>
            <th>Matched At</th>
          </tr>
        </thead>
        <tbody>
          ${{nuclei.map(finding => {{
            const severity = (finding.severity || 'INFO').toUpperCase();
            const templateId = finding.template_id || finding['template-id'] || 'N/A';
            const name = finding.name || '';
            const matchedAt = finding.matched_at || finding['matched-at'] || finding.url || '';
            return `
              <tr>
                <td><span class="severity-pill ${{severity}}">${{escapeHtml(severity)}}</span></td>
                <td>${{escapeHtml(templateId)}}</td>
                <td>${{escapeHtml(name)}}</td>
                <td>${{escapeHtml(matchedAt)}}</td>
              </tr>
            `;
          }}).join('')}}
        </tbody>
      </table>
    `;
  }} else {{
    html += '<p class="muted">No Nuclei findings</p>';
  }}
  html += '</div>';
  
  // Nikto section
  html += `<div class="section"><h2>Nikto Findings (${{nikto.length}})</h2>`;
  if (nikto.length) {{
    html += `
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Message</th>
            <th>Reference</th>
          </tr>
        </thead>
        <tbody>
          ${{nikto.map(finding => {{
            const severity = ((finding.severity || finding.risk) || 'INFO').toUpperCase();
            const message = finding.msg || finding.description || finding.raw || '';
            const reference = finding.uri || (finding.osvdb ? `OSVDB-${{finding.osvdb}}` : '') || '—';
            return `
              <tr>
                <td><span class="severity-pill ${{severity}}">${{escapeHtml(severity)}}</span></td>
                <td>${{escapeHtml(message)}}</td>
                <td>${{escapeHtml(reference)}}</td>
              </tr>
            `;
          }}).join('')}}
        </tbody>
      </table>
    `;
  }} else {{
    html += '<p class="muted">No Nikto findings</p>';
  }}
  html += '</div>';
  
  // Discovered URLs/Endpoints section
  html += `
    <div class="section">
      <h2>Discovered URLs (${{endpoints?.length || 0}})</h2>
      ${{endpoints && endpoints.length ? `
        <div style="max-height: 300px; overflow-y: auto; background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px;">
          ${{endpoints.map(url => `
            <div style="padding: 4px 0; border-bottom: 1px solid #1f2937;">
              <a href="${{escapeHtml(url)}}" target="_blank" rel="noopener noreferrer" style="color: #60a5fa; text-decoration: none; font-size: 0.9rem; word-break: break-all;">${{escapeHtml(url)}}</a>
            </div>
          `).join('')}}
        </div>
      ` : `<p class="muted">No URLs discovered yet. Run Waybackurls or GAU to find URLs for this domain.</p>`}}
    </div>
  `;
  
  // Comments section
  html += `
    <div class="section">
      <h2>Comments (${{comments.length}})</h2>
      <div style="margin-bottom: 16px;">
        <textarea id="comment-input" placeholder="Add a comment..." style="width: 100%; min-height: 80px; padding: 8px; background: #0f172a; border: 1px solid #334155; color: #e2e8f0; border-radius: 4px; font-family: inherit;"></textarea>
        <button class="btn" onclick="addComment()" style="margin-top: 8px;">Add Comment</button>
      </div>
      <div id="comments-list">
        ${{comments.length ? comments.map(c => `
          <div style="background: #0f172a; padding: 12px; margin-bottom: 8px; border-radius: 4px; border: 1px solid #334155;">
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
              <span class="muted" style="font-size: 0.875rem;">${{fmtTime(c.timestamp)}}</span>
              <button class="btn secondary small" onclick="deleteComment('${{escapeHtml(c.id)}}')" style="padding: 4px 8px; font-size: 0.75rem;">Delete</button>
            </div>
            <div>${{escapeHtml(c.text)}}</div>
          </div>
        `).join('') : '<p class="muted">No comments yet</p>'}}
      </div>
    </div>
  `;
  
  document.getElementById('content').innerHTML = html;
}}

async function markSubdomain(interesting) {{
  try {{
    const resp = await fetch('/api/subdomain/mark', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ domain, subdomain, interesting }})
    }});
    const result = await resp.json();
    if (result.success) {{
      loadSubdomainDetail(); // Reload to show updated state
    }} else {{
      alert('Error: ' + result.message);
    }}
  }} catch (err) {{
    alert('Error marking subdomain: ' + err.message);
  }}
}}

async function addComment() {{
  const input = document.getElementById('comment-input');
  const comment = input.value.trim();
  if (!comment) return;
  
  try {{
    const resp = await fetch('/api/subdomain/comment', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ domain, subdomain, comment, action: 'add' }})
    }});
    const result = await resp.json();
    if (result.success) {{
      input.value = '';
      loadSubdomainDetail(); // Reload to show new comment
    }} else {{
      alert('Error: ' + result.message);
    }}
  }} catch (err) {{
    alert('Error adding comment: ' + err.message);
  }}
}}

async function deleteComment(commentId) {{
  if (!confirm('Delete this comment?')) return;
  
  try {{
    const resp = await fetch('/api/subdomain/comment', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ domain, subdomain, comment_id: commentId, action: 'delete' }})
    }});
    const result = await resp.json();
    if (result.success) {{
      loadSubdomainDetail(); // Reload to show updated list
    }} else {{
      alert('Error: ' + result.message);
    }}
  }} catch (err) {{
    alert('Error deleting comment: ' + err.message);
  }}
}}

async function runContentDiscovery(tool) {{
  const statusDiv = document.getElementById('content-discovery-status');
  statusDiv.style.display = 'block';
  statusDiv.style.background = '#1e40af';
  statusDiv.style.color = '#bfdbfe';
  statusDiv.textContent = `Running ${{tool}} for ${{subdomain}}...`;
  
  try {{
    const resp = await fetch('/api/subdomain/run-tool', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ domain, subdomain, tool }})
    }});
    const result = await resp.json();
    if (result.success) {{
      statusDiv.style.background = '#065f46';
      statusDiv.style.color = '#a7f3d0';
      statusDiv.textContent = result.message || `${{tool}} completed successfully`;
      setTimeout(() => {{
        loadSubdomainDetail(); // Reload to show updated data
      }}, 2000);
    }} else {{
      statusDiv.style.background = '#7f1d1d';
      statusDiv.style.color = '#fca5a5';
      statusDiv.textContent = 'Error: ' + result.message;
    }}
  }} catch (err) {{
    statusDiv.style.background = '#7f1d1d';
    statusDiv.style.color = '#fca5a5';
    statusDiv.textContent = 'Error running ${{tool}}: ' + err.message;
  }}
}}

loadSubdomainDetail();
</script>
</body>
</html>
"""
