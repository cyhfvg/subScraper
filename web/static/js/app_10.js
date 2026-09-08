async function createBackup() {
  if (!createBackupBtn) return;
  
  const originalText = createBackupBtn.textContent;
  createBackupBtn.textContent = 'Creating...';
  createBackupBtn.disabled = true;
  
  try {
    const payload = {};
    if (backupNameInput && backupNameInput.value.trim()) {
      payload.name = backupNameInput.value.trim();
    }
    
    const resp = await fetch('/api/backup/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    
    if (data.success) {
      alert(`Backup created successfully: ${data.filename}`);
      if (backupNameInput) backupNameInput.value = '';
      await loadBackups();
    } else {
      alert(`Backup failed: ${data.message}`);
    }
  } catch (err) {
    alert(`Error creating backup: ${err.message}`);
  } finally {
    createBackupBtn.textContent = originalText;
    createBackupBtn.disabled = false;
  }
}

function downloadBackup(filename) {
  window.location.href = `/api/backup/download/${encodeURIComponent(filename)}`;
}

async function restoreBackup(filename) {
  if (!confirm(`Are you sure you want to restore from backup "${filename}"? This will overwrite current data.`)) {
    return;
  }
  
  try {
    const resp = await fetch('/api/backup/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename }),
    });
    const data = await resp.json();
    
    if (data.success) {
      alert(`Backup restored successfully. Reloading...`);
      window.location.reload();
    } else {
      alert(`Restore failed: ${data.message}`);
    }
  } catch (err) {
    alert(`Error restoring backup: ${err.message}`);
  }
}

async function deleteBackup(filename) {
  if (!confirm(`Are you sure you want to delete backup "${filename}"? This cannot be undone.`)) {
    return;
  }
  
  try {
    const resp = await fetch('/api/backup/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename }),
    });
    const data = await resp.json();
    
    if (data.success) {
      alert('Backup deleted successfully');
      await loadBackups();
    } else {
      alert(`Delete failed: ${data.message}`);
    }
  } catch (err) {
    alert(`Error deleting backup: ${err.message}`);
  }
}

if (createBackupBtn) {
  createBackupBtn.addEventListener('click', createBackup);
}

// Load backups when settings tab is opened
document.querySelectorAll('.settings-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    if (tab.getAttribute('data-tab') === 'backup') {
      loadBackups();
    }
  });
});

if (monitorForm) {
  monitorForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = {
      name: monitorName ? monitorName.value : '',
      url: monitorUrl ? monitorUrl.value : '',
      interval: monitorInterval ? monitorInterval.value : '',
    };
    if (monitorStatus) {
      monitorStatus.textContent = 'Saving...';
      monitorStatus.className = 'status';
    }
    try {
      const resp = await fetch('/api/monitors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (monitorStatus) {
        monitorStatus.textContent = data.message || 'Saved';
        monitorStatus.className = 'status ' + (data.success ? 'success' : 'error');
      }
      if (data.success) {
        monitorForm.reset();
        fetchState();
      }
    } catch (err) {
      if (monitorStatus) {
        monitorStatus.textContent = err.message;
        monitorStatus.className = 'status error';
      }
    }
  });
}

if (monitorsList) {
  monitorsList.addEventListener('click', (event) => {
    const removeBtn = event.target.closest('[data-remove-monitor]');
    if (removeBtn) {
      const id = removeBtn.getAttribute('data-remove-monitor');
      deleteMonitor(id, removeBtn);
    }
  });
}

// ================== LOGS VIEW ==================

function saveLogFilters() {
  const filters = {
    search: logSearch ? logSearch.value : '',
    source: logSourceFilter ? logSourceFilter.value : '',
    level: logLevelFilter ? logLevelFilter.value : ''
  };
  try {
    localStorage.setItem('logFilters', JSON.stringify(filters));
  } catch (e) {
    // Ignore localStorage errors
  }
}

function loadLogFilters() {
  try {
    const saved = localStorage.getItem('logFilters');
    if (saved) {
      const filters = JSON.parse(saved);
      if (logSearch) logSearch.value = filters.search || '';
      if (logSourceFilter) logSourceFilter.value = filters.source || '';
      if (logLevelFilter) logLevelFilter.value = filters.level || '';
      return filters;
    }
  } catch (e) {
    // Ignore localStorage errors
  }
  return { search: '', source: '', level: '' };
}

async function fetchAllLogs() {
  // Collect logs from all running jobs and history
  let logs = [];
  
  // Get logs from currently running jobs
  latestRunningJobs.forEach(job => {
    const jobLogs = job.logs || [];
    jobLogs.forEach(entry => {
      logs.push({
        timestamp: entry.ts || '',
        source: entry.source || 'unknown',
        text: entry.text || '',
        domain: job.domain || ''
      });
    });
  });
  
  // Get logs from history for all targets
  const targets = Object.keys(latestTargetsData);
  for (const domain of targets) {
    try {
      const resp = await fetch(`/api/history?domain=${encodeURIComponent(domain)}`);
      if (resp.ok) {
        const data = await resp.json();
        const events = data.events || [];
        events.forEach(entry => {
          logs.push({
            timestamp: entry.ts || '',
            source: entry.source || 'unknown',
            text: entry.text || '',
            domain: domain
          });
        });
      }
    } catch (err) {
      // Ignore fetch errors for individual domains
    }
  }
  
  // Sort by timestamp descending (newest first)
  logs.sort((a, b) => {
    const dateA = new Date(a.timestamp || 0);
    const dateB = new Date(b.timestamp || 0);
    return dateB - dateA;
  });
  
  return logs;
}

function filterLogs() {
  const searchTerm = (logSearch ? logSearch.value : '').toLowerCase();
  const sourceFilter = logSourceFilter ? logSourceFilter.value : '';
  const levelFilter = logLevelFilter ? logLevelFilter.value : '';
  
  filteredLogs = allLogs.filter(log => {
    // Text search
    if (searchTerm && !log.text.toLowerCase().includes(searchTerm) && !log.domain.toLowerCase().includes(searchTerm)) {
      return false;
    }
    
    // Source filter
    if (sourceFilter && log.source !== sourceFilter) {
      return false;
    }
    
    // Level filter (matches source for common cases)
    if (levelFilter) {
      const source = log.source.toLowerCase();
      if (levelFilter === 'error' && !source.includes('error')) {
        return false;
      }
      if (levelFilter === 'stderr' && !source.includes('stderr')) {
        return false;
      }
      if (levelFilter === 'command' && !log.text.startsWith('$')) {
        return false;
      }
      if (levelFilter === 'system' && source !== 'system' && source !== 'scheduler') {
        return false;
      }
    }
    
    return true;
  });
  
  saveLogFilters();
  renderLogs();
}

function renderLogs() {
  if (!logsTbody) return;
  
  if (filteredLogs.length === 0) {
    logsTbody.innerHTML = '<tr><td colspan="3" class="muted">No logs match your filters.</td></tr>';
    if (logsCount) logsCount.textContent = '0 logs';
    return;
  }
  
  const rows = filteredLogs.map(log => {
    const timestamp = fmtTime(log.timestamp);
    const sourceClass = log.source.toLowerCase().includes('error') || log.source.toLowerCase().includes('stderr') ? 'error-source' : '';
    return `
      <tr>
        <td data-sort-value="${escapeHtml(log.timestamp)}">${escapeHtml(timestamp)}</td>
        <td data-sort-value="${escapeHtml(log.source)}" class="${sourceClass}">
          <span title="${escapeHtml(log.domain)}">${escapeHtml(log.source)}</span>
        </td>
        <td data-sort-value="${escapeHtml(log.text)}" style="max-width: 600px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(log.text)}">
          ${escapeHtml(log.text)}
        </td>
      </tr>
    `;
  }).join('');
  
  logsTbody.innerHTML = rows;
  if (logsCount) logsCount.textContent = `${filteredLogs.length} logs (of ${allLogs.length} total)`;
  
  // Apply pagination if available
  if (logsPagination && logsTable) {
    initPagination(logsTable, logsPagination, DEFAULT_PAGE_SIZE);
  }
}

function populateLogSourceFilter() {
  if (!logSourceFilter) return;
  
  const sources = new Set();
  allLogs.forEach(log => {
    if (log.source) sources.add(log.source);
  });
  
  const currentValue = logSourceFilter.value;
  const sortedSources = Array.from(sources).sort();
  
  logSourceFilter.innerHTML = '<option value="">All sources</option>' +
    sortedSources.map(source => `<option value="${escapeHtml(source)}">${escapeHtml(source)}</option>`).join('');
  
  // Restore previous selection if it still exists
  if (currentValue && sortedSources.includes(currentValue)) {
    logSourceFilter.value = currentValue;
  }
}

async function updateLogsView() {
  allLogs = await fetchAllLogs();
  populateLogSourceFilter();
  filterLogs();
}

// Event listeners for logs
if (logSearch) {
  logSearch.addEventListener('input', filterLogs);
}

if (logSourceFilter) {
  logSourceFilter.addEventListener('change', filterLogs);
}

if (logLevelFilter) {
  logLevelFilter.addEventListener('change', filterLogs);
}

if (logClearFilters) {
  logClearFilters.addEventListener('click', () => {
    if (logSearch) logSearch.value = '';
    if (logSourceFilter) logSourceFilter.value = '';
    if (logLevelFilter) logLevelFilter.value = '';
    filterLogs();
  });
}

// Load saved filters on page load
loadLogFilters();

// ================== GALLERY RENDERING ==================

const galleryTargetSelect = document.getElementById('gallery-target-select');
const galleryGrid = document.getElementById('gallery-grid');

function renderGallery(targets) {
  // Update target dropdown
  if (galleryTargetSelect) {
    const options = '<option value="">-- Select a target --</option>' +
      Object.keys(targets).sort().map(domain => 
        `<option value="${escapeHtml(domain)}">${escapeHtml(domain)}</option>`
      ).join('');
    galleryTargetSelect.innerHTML = options;
  }
}

if (galleryTargetSelect) {
  galleryTargetSelect.addEventListener('change', async (e) => {
    const domain = e.target.value;
    if (!domain || !galleryGrid) {
      if (galleryGrid) galleryGrid.innerHTML = '';
      return;
    }
    
    galleryGrid.innerHTML = '<div class="section-placeholder">Loading screenshots...</div>';
    
    try {
      const resp = await fetch(`/api/gallery/${encodeURIComponent(domain)}`);
      if (!resp.ok) throw new Error('Failed to load gallery');
      const data = await resp.json();
      
      if (!data.success) {
        galleryGrid.innerHTML = `<div class="section-placeholder">${escapeHtml(data.message || 'Failed to load gallery')}</div>`;
        return;
      }
      
      const screenshots = data.screenshots || [];
      if (screenshots.length === 0) {
        galleryGrid.innerHTML = '<div class="section-placeholder">No screenshots available for this target.</div>';
        return;
      }
      
      const html = screenshots.map(shot => {
        const statusClass = shot.status_code >= 200 && shot.status_code < 300 ? 'status-2xx' :
                            shot.status_code >= 300 && shot.status_code < 400 ? 'status-3xx' :
                            shot.status_code >= 400 && shot.status_code < 500 ? 'status-4xx' : 'status-5xx';
        const statusBadge = shot.status_code ? `<span class="status-badge ${statusClass}">${shot.status_code}</span>` : '';
        
        return `
          <div class="gallery-card">
            <img class="gallery-image" src="/screenshots/${escapeHtml(shot.path)}" 
                 alt="${escapeHtml(shot.subdomain)}" 
                 onclick="window.open('/screenshots/${escapeHtml(shot.path)}', '_blank')" />
            <div class="gallery-info">
              <div class="gallery-subdomain">${escapeHtml(shot.subdomain)}</div>
              <a href="${escapeHtml(shot.url)}" target="_blank" class="gallery-url">${escapeHtml(shot.url)}</a>
              <div class="gallery-meta">
                ${statusBadge}
                ${shot.title ? `<span class="badge">${escapeHtml(shot.title)}</span>` : ''}
              </div>
            </div>
          </div>
        `;
      }).join('');
      
      galleryGrid.innerHTML = html;
    } catch (err) {
      galleryGrid.innerHTML = `<div class="section-placeholder">Error: ${escapeHtml(err.message)}</div>`;
    }
  });
}

// ================== FILTER PERSISTENCE ==================

// Save and restore report filters
function saveReportFilters(domain, filters) {
  try {
    const key = `reportFilters_${domain}`;
    localStorage.setItem(key, JSON.stringify(filters));
  } catch (e) {
    // Ignore localStorage errors
  }
}

function loadReportFilters(domain) {
  try {
    const key = `reportFilters_${domain}`;
    const saved = localStorage.getItem(key);
    return saved ? JSON.parse(saved) : null;
  } catch (e) {
    return null;
  }
}

// Save checkbox states
