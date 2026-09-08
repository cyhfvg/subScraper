function renderSystemResources(data) {
  const resourcesBody = document.getElementById('resources-body');
  if (!resourcesBody) return;
  
  if (!data || !data.current || !data.current.available) {
    const errorMsg = data && data.current ? data.current.error : 'System resource monitoring unavailable';
    resourcesBody.innerHTML = `<div class="section-placeholder">⚠️ ${escapeHtml(errorMsg)}</div>`;
    return;
  }
  
  const current = data.current;
  const history = data.history || [];
  
  // Helper to get status class
  function getStatusClass(percent, criticalThreshold, warningThreshold) {
    if (percent >= criticalThreshold) return 'critical';
    if (percent >= warningThreshold) return 'warning';
    return 'normal';
  }
  
  // CPU metrics
  const cpu = current.cpu || {};
  const cpuPercent = cpu.percent || 0;
  const cpuClass = getStatusClass(cpuPercent, 90, 75);
  
  // Memory metrics
  const memory = current.memory || {};
  const memPercent = memory.percent || 0;
  const memClass = getStatusClass(memPercent, 90, 80);
  
  // Disk metrics
  const disk = current.disk || {};
  const diskPercent = disk.percent || 0;
  const diskClass = getStatusClass(diskPercent, 95, 85);
  
  // Process metrics
  const process = current.process || {};
  
  // Warnings
  const warnings = current.warnings || [];
  let warningsHtml = '';
  if (warnings.length > 0) {
    const criticalWarnings = warnings.filter(w => w.severity === 'critical');
    const normalWarnings = warnings.filter(w => w.severity !== 'critical');
    
    const warningItems = [...criticalWarnings, ...normalWarnings].map(w => {
      const icon = w.severity === 'critical' ? '🔴' : '⚠️';
      const cls = w.severity === 'critical' ? 'critical' : 'warning';
      return `<div class="resource-warning ${cls}">${icon} ${escapeHtml(w.message)}</div>`;
    }).join('');
    
    warningsHtml = `
      <div class="resource-warnings-section">
        <h3>⚠️ Resource Warnings (${warnings.length})</h3>
        ${warningItems}
      </div>
    `;
  }
  
  // Build main metrics grid
  const metricsHtml = `
    <div class="resource-grid">
      <div class="resource-card ${cpuClass}">
        <h3>CPU Usage</h3>
        <div class="resource-metric">${cpuPercent.toFixed(1)}%</div>
        <div class="muted">${cpu.count_logical || 0} logical cores</div>
        <div class="worker-progress">${renderProgress(cpuPercent, cpuClass === 'normal' ? 'completed' : 'running')}</div>
        <div class="resource-details">
          <div class="resource-detail-item">
            <span class="resource-label">Load Average:</span>
            <span class="resource-value">${cpu.load_avg_1m || 0} / ${cpu.load_avg_5m || 0} / ${cpu.load_avg_15m || 0}</span>
          </div>
          ${cpu.frequency_mhz ? `
          <div class="resource-detail-item">
            <span class="resource-label">Frequency:</span>
            <span class="resource-value">${cpu.frequency_mhz} MHz</span>
          </div>
          ` : ''}
        </div>
      </div>
      
      <div class="resource-card ${memClass}">
        <h3>Memory Usage</h3>
        <div class="resource-metric">${memPercent.toFixed(1)}%</div>
        <div class="muted">${memory.used_gb || 0} / ${memory.total_gb || 0} GB</div>
        <div class="worker-progress">${renderProgress(memPercent, memClass === 'normal' ? 'completed' : 'running')}</div>
        <div class="resource-details">
          <div class="resource-detail-item">
            <span class="resource-label">Available:</span>
            <span class="resource-value">${memory.available_gb || 0} GB</span>
          </div>
        </div>
      </div>
      
      <div class="resource-card ${diskClass}">
        <h3>Disk Usage</h3>
        <div class="resource-metric">${diskPercent.toFixed(1)}%</div>
        <div class="muted">${disk.used_gb || 0} / ${disk.total_gb || 0} GB</div>
        <div class="worker-progress">${renderProgress(diskPercent, diskClass === 'normal' ? 'completed' : 'running')}</div>
        <div class="resource-details">
          <div class="resource-detail-item">
            <span class="resource-label">Free:</span>
            <span class="resource-value">${disk.free_gb || 0} GB</span>
          </div>
        </div>
      </div>
      
      <div class="resource-card">
        <h3>Application</h3>
        <div class="resource-metric">${process.cpu_percent || 0}%</div>
        <div class="muted">${process.memory_mb || 0} MB used</div>
        <div class="resource-details">
          <div class="resource-detail-item">
            <span class="resource-label">Processes:</span>
            <span class="resource-value">${process.count || 1}</span>
          </div>
          <div class="resource-detail-item">
            <span class="resource-label">Threads:</span>
            <span class="resource-value">${process.threads || 0}</span>
          </div>
          <div class="resource-detail-item">
            <span class="resource-label">PID:</span>
            <span class="resource-value">${process.pid || 'N/A'}</span>
          </div>
        </div>
      </div>
    </div>
  `;
  
  // Build history chart (simple ASCII-style visualization)
  let historyHtml = '';
  if (history.length > 0) {
    const recentHistory = history.slice(-60); // Last 5 minutes at 5s intervals
    const maxDataPoints = Math.min(recentHistory.length, 60);
    const step = Math.ceil(recentHistory.length / maxDataPoints);
    const chartData = [];
    
    for (let i = 0; i < recentHistory.length; i += step) {
      chartData.push(recentHistory[i]);
    }
    
    // Create simple chart representation
    const chartWidth = 100;
    const cpuPoints = chartData.map(d => d.cpu_percent || 0);
    const memPoints = chartData.map(d => d.memory_percent || 0);
    
    const cpuLine = cpuPoints.map(v => Math.round(v)).join(', ');
    const memLine = memPoints.map(v => Math.round(v)).join(', ');
    
    historyHtml = `
      <div class="resource-history">
        <h3>Usage History (Last 5 Minutes)</h3>
        <div class="resource-history-grid">
          <div class="resource-history-item">
            <span class="resource-history-label">CPU:</span>
            <div class="resource-history-sparkline">
              ${cpuPoints.map((v, i) => {
                const height = Math.min(100, Math.max(5, v));
                const color = v > 90 ? '#dc2626' : v > 75 ? '#f59e0b' : '#10b981';
                return `<div class="sparkline-bar" style="height: ${height}%; background: ${color};" title="${v.toFixed(1)}%"></div>`;
              }).join('')}
            </div>
            <span class="resource-history-current">${cpuPercent.toFixed(1)}%</span>
          </div>
          <div class="resource-history-item">
            <span class="resource-history-label">Memory:</span>
            <div class="resource-history-sparkline">
              ${memPoints.map((v, i) => {
                const height = Math.min(100, Math.max(5, v));
                const color = v > 90 ? '#dc2626' : v > 80 ? '#f59e0b' : '#3b82f6';
                return `<div class="sparkline-bar" style="height: ${height}%; background: ${color};" title="${v.toFixed(1)}%"></div>`;
              }).join('')}
            </div>
            <span class="resource-history-current">${memPercent.toFixed(1)}%</span>
          </div>
        </div>
      </div>
    `;
  }
  
  // Additional system info
  const networkHtml = `
    <div class="resource-network">
      <h3>Network I/O</h3>
      <div class="resource-network-grid">
        <div class="resource-network-item">
          <span class="resource-label">Sent:</span>
          <span class="resource-value">${formatBytes(current.network?.bytes_sent || 0)}</span>
        </div>
        <div class="resource-network-item">
          <span class="resource-label">Received:</span>
          <span class="resource-value">${formatBytes(current.network?.bytes_recv || 0)}</span>
        </div>
        <div class="resource-network-item">
          <span class="resource-label">Packets Sent:</span>
          <span class="resource-value">${formatNumber(current.network?.packets_sent || 0)}</span>
        </div>
        <div class="resource-network-item">
          <span class="resource-label">Packets Received:</span>
          <span class="resource-value">${formatNumber(current.network?.packets_recv || 0)}</span>
        </div>
      </div>
    </div>
  `;
  
  resourcesBody.innerHTML = warningsHtml + metricsHtml + historyHtml + networkHtml;
}

// Helper functions for formatting
