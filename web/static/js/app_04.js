function toggleNodeMap(mapId) {
  const mapEl = document.getElementById(mapId);
  if (mapEl) {
    const isVisible = mapEl.style.display !== 'none';
    mapEl.style.display = isVisible ? 'none' : 'block';
    if (!isVisible) {
      // Redraw when shown
      const canvasId = `${mapId}-canvas`;
      const canvas = document.getElementById(canvasId);
      if (canvas && canvas.dataset.domain) {
        drawNodeMap(canvas);
      }
    }
  }
}

function initNodeMap(domain, info, mapId) {
  const canvasId = `${mapId}-canvas`;
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  
  const subs = (info && info.subdomains) || {};
  const subdomains = Object.keys(subs).sort();
  const totalSubdomainCount = info.total_subdomains !== undefined ? info.total_subdomains : subdomains.length;
  
  // Store data in canvas dataset
  canvas.dataset.domain = domain;
  canvas.dataset.subdomains = JSON.stringify(subdomains);
  canvas.dataset.totalSubdomains = totalSubdomainCount;
  
  // Set actual canvas resolution
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * window.devicePixelRatio;
  canvas.height = rect.height * window.devicePixelRatio;
  
  // Draw the node map
  drawNodeMap(canvas);
  
  // Add click handler
  canvas.addEventListener('click', (e) => {
    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) * (canvas.width / rect.width);
    const y = (e.clientY - rect.top) * (canvas.height / rect.height);
    handleNodeMapClick(canvas, x, y);
  });
}

function drawNodeMap(canvas) {
  const ctx = canvas.getContext('2d');
  const domain = canvas.dataset.domain;
  const subdomains = JSON.parse(canvas.dataset.subdomains || '[]');
  const totalSubdomains = parseInt(canvas.dataset.totalSubdomains) || subdomains.length;
  
  const width = canvas.width;
  const height = canvas.height;
  
  // Clear canvas
  ctx.clearRect(0, 0, width, height);
  
  // Draw background
  ctx.fillStyle = '#050b18';
  ctx.fillRect(0, 0, width, height);
  
  if (subdomains.length === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = `${16 * window.devicePixelRatio}px system-ui`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('No subdomains to display', width / 2, height / 2);
    return;
  }
  
  // Calculate layout
  const centerX = width / 2;
  const centerY = height / 2;
  const domainRadius = 30 * window.devicePixelRatio;
  const subRadius = 15 * window.devicePixelRatio;
  const orbitRadius = Math.min(width, height) * 0.35;
  
  // Store node positions for click detection
  const nodes = [];
  
  // Draw connections from domain to subdomains
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 2 * window.devicePixelRatio;
  subdomains.forEach((sub, i) => {
    const angle = (i / subdomains.length) * Math.PI * 2 - Math.PI / 2;
    const x = centerX + Math.cos(angle) * orbitRadius;
    const y = centerY + Math.sin(angle) * orbitRadius;
    
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.lineTo(x, y);
    ctx.stroke();
  });
  
  // Draw subdomain nodes
  subdomains.forEach((sub, i) => {
    const angle = (i / subdomains.length) * Math.PI * 2 - Math.PI / 2;
    const x = centerX + Math.cos(angle) * orbitRadius;
    const y = centerY + Math.sin(angle) * orbitRadius;
    
    // Node circle
    ctx.fillStyle = '#2563eb';
    ctx.beginPath();
    ctx.arc(x, y, subRadius, 0, Math.PI * 2);
    ctx.fill();
    
    // Node border
    ctx.strokeStyle = '#60a5fa';
    ctx.lineWidth = 2 * window.devicePixelRatio;
    ctx.stroke();
    
    // Store for click detection
    nodes.push({ x, y, radius: subRadius, subdomain: sub, type: 'subdomain' });
    
    // Label (only show if space allows)
    if (subdomains.length < 20) {
      ctx.fillStyle = '#e2e8f0';
      ctx.font = `${11 * window.devicePixelRatio}px system-ui`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const labelY = y + subRadius + 15 * window.devicePixelRatio;
      const shortLabel = sub.length > 15 ? sub.substring(0, 12) + '...' : sub;
      ctx.fillText(shortLabel, x, labelY);
    }
  });
  
  // Draw domain node (center)
  ctx.fillStyle = '#1d4ed8';
  ctx.beginPath();
  ctx.arc(centerX, centerY, domainRadius, 0, Math.PI * 2);
  ctx.fill();
  
  ctx.strokeStyle = '#3b82f6';
  ctx.lineWidth = 3 * window.devicePixelRatio;
  ctx.stroke();
  
  // Domain label
  ctx.fillStyle = '#ffffff';
  ctx.font = `bold ${14 * window.devicePixelRatio}px system-ui`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  const domainLabel = domain.length > 12 ? domain.substring(0, 10) + '...' : domain;
  ctx.fillText(domainLabel, centerX, centerY);
  
  // Store domain node
  nodes.push({ x: centerX, y: centerY, radius: domainRadius, domain: domain, type: 'domain' });
  
  // Store nodes in canvas dataset for click handling
  canvas.dataset.nodes = JSON.stringify(nodes);
  
  // Draw legend
  ctx.fillStyle = '#94a3b8';
  ctx.font = `${10 * window.devicePixelRatio}px system-ui`;
  ctx.textAlign = 'left';
  const legendText = subdomains.length < totalSubdomains 
    ? `${totalSubdomains} subdomains (showing ${subdomains.length})`
    : `${totalSubdomains} subdomains`;
  ctx.fillText(legendText, 10 * window.devicePixelRatio, height - 10 * window.devicePixelRatio);
}

function handleNodeMapClick(canvas, x, y) {
  const nodes = JSON.parse(canvas.dataset.nodes || '[]');
  const domain = canvas.dataset.domain;
  
  // Check if click is on any node
  for (const node of nodes) {
    const dx = x - node.x;
    const dy = y - node.y;
    const distance = Math.sqrt(dx * dx + dy * dy);
    
    if (distance <= node.radius) {
      if (node.type === 'subdomain') {
        // Navigate to subdomain detail page
        window.location.href = `/subdomain/${encodeURIComponent(domain)}/${encodeURIComponent(node.subdomain)}`;
      } else if (node.type === 'domain') {
        // Could navigate to domain report or do nothing
        const reportsLink = document.querySelector(`a[href="#reports"]`);
        if (reportsLink) {
          reportsLink.click();
          setTimeout(() => {
            const domainCard = document.querySelector(`.report-nav-card[data-report-domain="${domain}"]`);
            if (domainCard) {
              domainCard.click();
            }
          }, 100);
        }
      }
      break;
    }
  }
}

function renderWorkflowDiagram() {
  const diagram = document.getElementById('workflow-diagram');
  if (!diagram) return;
  
  const html = `
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 1: Subdomain Enumeration</div>
      <div class="workflow-tools">
        <span class="workflow-tool enumeration">Amass</span>
        <span class="workflow-tool enumeration">Subfinder</span>
        <span class="workflow-tool enumeration">Assetfinder</span>
        <span class="workflow-tool enumeration">Findomain</span>
        <span class="workflow-tool enumeration">Sublist3r</span>
        <span class="workflow-tool enumeration">crt.sh</span>
        <span class="workflow-tool enumeration">GitHub-Subdomains</span>
        <span class="workflow-tool enumeration">DNSx</span>
      </div>
      <div class="workflow-description">Passive and active subdomain discovery using multiple data sources</div>
    </div>
    
    <div style="text-align:center; margin:16px 0;">
      <span class="workflow-arrow">↓</span>
    </div>
    
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 2: HTTP Probing</div>
      <div class="workflow-tools">
        <span class="workflow-tool probing">HTTPX</span>
      </div>
      <div class="workflow-description">Probe subdomains for live HTTP services and gather response metadata</div>
    </div>
    
    <div style="text-align:center; margin:16px 0;">
      <span class="workflow-arrow">↓</span>
    </div>
    
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 3: Visual Capture</div>
      <div class="workflow-tools">
        <span class="workflow-tool capture">Gowitness</span>
      </div>
      <div class="workflow-description">Capture screenshots of live web applications for visual analysis</div>
    </div>
    
    <div style="text-align:center; margin:16px 0;">
      <span class="workflow-arrow">↓</span>
    </div>
    
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 4: Vulnerability Scanning</div>
      <div class="workflow-tools">
        <span class="workflow-tool scanning">Nuclei</span>
      </div>
      <div class="workflow-description">Template-based vulnerability scanning, using the official template set plus the templates bundled with this repo</div>
    </div>
    
    <div style="text-align:center; margin:16px 0;">
      <span class="workflow-arrow">↓</span>
    </div>
    
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 5: JavaScript Analysis</div>
      <div class="workflow-tools">
        <span class="workflow-tool js-analysis">JS Scan</span>
      </div>
      <div class="workflow-description">Fetches JavaScript from live hosts and archived URLs, then extracts secrets, hidden endpoints and parameter names. Results appear in the JS Findings card above and on each domain page.</div>
    </div>
    
    <div style="text-align:center; margin:16px 0;">
      <span class="workflow-arrow">↓</span>
    </div>
    
    <div class="workflow-stage">
      <div class="workflow-stage-title">Phase 6: Web Server Scanning</div>
      <div class="workflow-tools">
        <span class="workflow-tool scanning">Nikto</span>
      </div>
      <div class="workflow-description">Web server misconfiguration and dated-software checks. Slow, and skipped when a run opts out of it.</div>
    </div>
    
    <div style="margin-top:24px; padding:16px; background:#0b152c; border-radius:12px; border:1px solid #1f2937;">
      <div style="color:#fbbf24; font-weight:600; margin-bottom:8px;">📋 Manual, from subdomain pages</div>
      <div class="workflow-tools">
        <span class="workflow-tool brute-force">FFUF</span>
        <span class="workflow-tool url-discovery">Waybackurls</span>
        <span class="workflow-tool url-discovery">GAU</span>
      </div>
      <div class="workflow-description">Vhost brute-forcing and archived-URL discovery are triggered per subdomain, not by the pipeline. Their URLs feed the JS scan on the next run.</div>
    </div>
  `;
  
  diagram.innerHTML = html;
}

function renderWorkers(workers) {
  if (!workers || !workers.job_slots) {
    workersBody.innerHTML = '<div class="section-placeholder">No worker data.</div>';
    return;
  }
  const job = workers.job_slots || {};
  const dynamicMode = workers.dynamic_mode || {};
  const autoBackup = workers.auto_backup || {};
  
  const jobPct = job.limit ? Math.min(100, Math.round((job.active || 0) / job.limit * 100)) : 0;
  
  // Dynamic mode indicator
  let dynamicIndicator = '';
  if (dynamicMode.enabled) {
    dynamicIndicator = `<div class="badge" style="background: #3b82f6; margin-top: 4px;">🔄 Dynamic Mode Active</div>`;
  }
  
  const jobCard = `
    <div class="worker-card">
      <h3>Job Slots</h3>
      <div class="metric">${job.active || 0}/${job.limit || 1}</div>
      <div class="muted">${job.queue || 0} queued</div>
      ${dynamicIndicator}
      <div class="worker-progress">${renderProgress(jobPct, (job.active || 0) >= (job.limit || 1) ? 'running' : 'completed')}</div>
    </div>
  `;
  
  // Add dynamic mode card if enabled
  let dynamicCard = '';
  if (dynamicMode.enabled) {
    dynamicCard = `
      <div class="worker-card">
        <h3>Dynamic Mode</h3>
        <div class="metric">${dynamicMode.current_jobs || 1}</div>
        <div class="muted">Range: ${dynamicMode.base_jobs || 1}–${dynamicMode.max_jobs || 10}</div>
        <div class="muted">CPU &lt; ${dynamicMode.cpu_threshold || 75}% · Mem &lt; ${dynamicMode.memory_threshold || 80}%</div>
      </div>
    `;
  }
  
  // Add auto-backup card if enabled
  let backupCard = '';
  if (autoBackup.enabled) {
    const nextBackup = autoBackup.next_backup ? new Date(autoBackup.next_backup).toLocaleTimeString() : 'N/A';
    backupCard = `
      <div class="worker-card">
        <h3>Auto-Backup</h3>
        <div class="metric">💾 Active</div>
        <div class="muted">Next: ${nextBackup}</div>
        <div class="muted">Keep last ${autoBackup.max_count || 10}</div>
      </div>
    `;
  }
  
  // Add rate limiting card
  const rateLimiting = workers.rate_limiting || {};
  const currentDelay = rateLimiting.current_delay || 0;
  const maxBackoff = rateLimiting.max_auto_backoff || 30;
  const timeoutTracker = rateLimiting.timeout_tracker || {};
  const activeRateLimits = Object.keys(timeoutTracker).length;
  
  let rateLimitStatus = 'inactive';
  let rateLimitClass = 'muted';
  if (currentDelay > 0) {
    rateLimitStatus = 'active';
    rateLimitClass = 'warning';
  }
  
  const rateLimitCard = `
    <div class="worker-card ${currentDelay > 0 ? 'rate-limit-active' : ''}">
      <h3>Rate Limiting</h3>
      <div class="metric ${rateLimitClass}">${currentDelay.toFixed(1)}s</div>
      <div class="muted">delay between calls</div>
      ${activeRateLimits > 0 ? `<div class="warning">⚠️ ${activeRateLimits} tracked domain(s)</div>` : ''}
    </div>
  `;
  
  const tools = workers.tools || {};
  const toolCards = Object.keys(tools).sort().map(name => {
    const info = tools[name] || {};
    const limit = info.limit;
    const active = info.active || 0;
    const queued = info.queued || 0;
    
    // Handle tools with and without concurrency gates
    if (limit == null) {
      // Tool without gate - just show as available
      return `
        <div class="worker-card">
          <h3>${escapeHtml(name)}</h3>
          <div class="metric">Available</div>
          <div class="muted">no concurrency limit</div>
        </div>
      `;
    } else {
      // Tool with gate - show active/limit and queued items
      const pct = limit ? Math.min(100, Math.round(active / limit * 100)) : 0;
      const queueInfo = queued > 0 ? `<div class="muted" style="margin-top: 4px;">📋 ${queued} queued</div>` : '';
      return `
        <div class="worker-card">
          <h3>${escapeHtml(name)}</h3>
          <div class="metric">${active}/${limit}</div>
          <div class="muted">slots in use</div>
          ${queueInfo}
          <div class="worker-progress">${renderProgress(pct, active >= limit ? 'running' : 'completed')}</div>
        </div>
      `;
    }
  }).join('') || '<div class="section-placeholder">No tool data.</div>';
  workersBody.innerHTML = `<div class="worker-grid">${jobCard}${dynamicCard}${backupCard}${rateLimitCard}${toolCards}</div>`;
}

