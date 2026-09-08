function fmtTime(value) {
  if (!value) return 'N/A';
  const d = new Date(value);
  if (isNaN(d.getTime())) return escapeHtml(value);
  return d.toLocaleString();
}

function normalizeSeverity(value, fallback = 'INFO') {
  if (value === undefined || value === null) return fallback;
  const text = String(value).trim().toUpperCase();
  if (!text) return fallback;
  if (SEVERITY_RANK[text] === undefined) return fallback;
  return text;
}

function severityRank(value) {
  const key = value || 'INFO';
  if (SEVERITY_RANK[key] === undefined) return SEVERITY_RANK.INFO;
  return SEVERITY_RANK[key];
}

function severityIsHigher(candidate, current) {
  return severityRank(candidate) < severityRank(current);
}

function formatSeverityLabel(value) {
  if (!value || value === 'NONE') return 'None';
  return value.charAt(0) + value.slice(1).toLowerCase();
}

function getPaginationState(table) {
  return table && table._paginationState;
}

function initPagination(table, pagerEl, pageSize = DEFAULT_PAGE_SIZE) {
  if (!table || !pagerEl) return;
  const state = {
    table,
    pagerEl,
    pageSize: Math.max(1, pageSize || DEFAULT_PAGE_SIZE),
    currentPage: 1,
    totalPages: 1,
  };
  if (pagerEl._paginationHandler) {
    pagerEl.removeEventListener('click', pagerEl._paginationHandler);
  }
  const handleClick = (event) => {
    const btn = event.target.closest('[data-page-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-page-action');
    if (action === 'prev') {
      state.currentPage = Math.max(1, state.currentPage - 1);
    } else if (action === 'next') {
      state.currentPage = Math.min(state.totalPages, state.currentPage + 1);
    } else if (action === 'first') {
      state.currentPage = 1;
    } else if (action === 'last') {
      state.currentPage = state.totalPages;
    }
    refreshPagination(table);
  };
  pagerEl._paginationHandler = handleClick;
  pagerEl.addEventListener('click', handleClick);
  table._paginationState = state;
  refreshPagination(table);
}

function refreshPagination(table) {
  const state = getPaginationState(table);
  if (!state) return;
  const rows = Array.from(table.tBodies[0] ? table.tBodies[0].rows : []);
  let visibleCount = 0;
  rows.forEach(row => {
    if (row.dataset.filterHidden === undefined) {
      row.dataset.filterHidden = 'false';
    }
    if (row.dataset.filterHidden === 'true') {
      row.style.display = 'none';
    }
  });
  rows.forEach(row => {
    if (row.dataset.filterHidden === 'true') return;
    visibleCount += 1;
  });
  state.totalPages = Math.max(1, Math.ceil(visibleCount / state.pageSize));
  if (state.currentPage > state.totalPages) {
    state.currentPage = state.totalPages;
  }
  let visibleIndex = 0;
  const start = (state.currentPage - 1) * state.pageSize;
  const end = start + state.pageSize;
  rows.forEach(row => {
    if (row.dataset.filterHidden === 'true') {
      row.style.display = 'none';
      return;
    }
    const inPage = visibleIndex >= start && visibleIndex < end;
    row.style.display = inPage ? '' : 'none';
    visibleIndex += 1;
  });
  const pagerEl = state.pagerEl;
  if (!pagerEl) return;
  if (state.totalPages <= 1) {
    pagerEl.innerHTML = '';
    return;
  }
  pagerEl.innerHTML = `
    <span class="page-info">${visibleCount} rows</span>
    <button data-page-action="first" ${state.currentPage === 1 ? 'disabled' : ''}>&laquo;</button>
    <button data-page-action="prev" ${state.currentPage === 1 ? 'disabled' : ''}>&lsaquo;</button>
    <span>Page ${state.currentPage} / ${state.totalPages}</span>
    <button data-page-action="next" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&rsaquo;</button>
    <button data-page-action="last" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&raquo;</button>
  `;
}

function makeSortable(table) {
  if (!table) return;
  const headers = table.querySelectorAll('th[data-sort-key]');
  headers.forEach((th, index) => {
    th.addEventListener('click', () => {
      const nextDir = th.dataset.sortDir === 'asc' ? 'desc' : 'asc';
      headers.forEach(header => delete header.dataset.sortDir);
      th.dataset.sortDir = nextDir;
      const type = th.dataset.sortType || 'text';
      const multiplier = nextDir === 'asc' ? 1 : -1;
      const rows = Array.from(table.tBodies[0].rows);
      rows.sort((a, b) => {
        const aVal = getCellSortValue(a.cells[index], type);
        const bVal = getCellSortValue(b.cells[index], type);
        if (aVal < bVal) return -1 * multiplier;
        if (aVal > bVal) return 1 * multiplier;
        return 0;
      });
      rows.forEach(row => table.tBodies[0].appendChild(row));
      refreshPagination(table);
    });
  });
}

function getCellSortValue(cell, type) {
  if (!cell) return '';
  const raw = cell.dataset.sortValue !== undefined ? cell.dataset.sortValue : cell.textContent.trim();
  if (type === 'number') {
    const num = parseFloat(raw);
    return isNaN(num) ? 0 : num;
  }
  return raw.toLowerCase();
}

function renderProgress(value, status) {
  const width = Math.max(0, Math.min(100, value || 0));
  return `<div class="progress-bar"><div class="progress-inner ${statusClass(status)}" style="width:${width}%"></div></div>`;
}

function linkifyLogText(text) {
  // Escape the text first
  const escaped = escapeHtml(text || '');
  
  // Pattern to match result file names (nikto_*.json, nuclei_*.json, httpx_*.json, etc.)
  const filePattern = /(nikto_[a-zA-Z0-9._-]+\.json|nuclei_[a-zA-Z0-9._-]+\.json|httpx_[a-zA-Z0-9._-]+\.json|ffuf_[a-zA-Z0-9._-]+\.json)/g;
  
  // Replace file references with download links
  return escaped.replace(filePattern, (match) => {
    // Create a download link for the JSON file using the /results/ endpoint
    return `<a href="/results/${match}" download="${match}" class="log-file-link" title="Download ${match}">${match}</a>`;
  });
}

function renderLogEntries(logs) {
  const safeLogs = Array.isArray(logs) ? logs : [];
  if (!safeLogs.length) {
    return '<p class="muted">No output yet.</p>';
  }
  return safeLogs.slice(-200).map(entry => {
    const linkedText = linkifyLogText(entry.text || '');
    return `
      <div class="log-entry">
        <div class="log-meta">${fmtTime(entry.ts)} — ${escapeHtml(entry.source || 'app')}</div>
        <pre class="log-text">${linkedText}</pre>
      </div>
    `;
  }).join('');
}

function renderJobControls(job) {
  if (!job || !job.domain) return '';
  if (job.status === 'running') {
    return `<div class="job-actions"><button class="btn secondary small" data-pause-job="${escapeHtml(job.domain)}">Pause</button></div>`;
  }
  if (job.status === 'paused' || job.status === 'pausing') {
    return `<div class="job-actions"><button class="btn small" data-resume-job="${escapeHtml(job.domain)}">Resume</button></div>`;
  }
  return '';
}

function renderJobStep(name, info = {}, domain = '') {
  const status = info.status || 'pending';
  const message = info.message || '';
  const pct = info.progress !== undefined ? info.progress : (status === 'completed' ? 100 : 0);
  
  // Show skip button for pending/running steps (not completed, skipped, or error)
  const canSkip = status === 'pending' || status === 'running' || status === 'queued';
  const skipBtn = canSkip && domain ? 
    `<button class="btn secondary small" data-skip-step="${escapeHtml(domain)}" data-step-name="${escapeHtml(name)}" style="margin-left: 8px;">Skip</button>` : 
    '';
  
  return `
    <div class="step-row">
      <div class="step-header">
        <span class="step-name">${escapeHtml(name.toUpperCase())}</span>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="status-pill ${statusClass(status)}">${statusLabel(status)}</span>
          ${skipBtn}
        </div>
      </div>
      <p class="muted">${escapeHtml(message)}</p>
      ${renderProgress(pct, status)}
    </div>
  `;
}

// Pagination state for jobs view
let jobsPaginationState = {
  currentPage: 1,
  pageSize: 10,  // Show 10 jobs per page for performance
  totalPages: 1
};

function renderJobs(jobs) {
  const all = Array.isArray(jobs) ? jobs : [];
  const running = all.filter(job => job.status !== 'queued');
  const activeJobs = running.filter(job => !job.completed_at);
  const completedJobs = running.filter(job => job.completed_at);
  
  // Update the stat to show active + completed
  statActive.textContent = `${activeJobs.length}${completedJobs.length > 0 ? ` (+ ${completedJobs.length} completed)` : ''}`;
  
  if (!running.length) {
    jobsList.innerHTML = '<div class="section-placeholder">No active jobs.</div>';
    const pagerEl = document.getElementById('jobs-pagination');
    if (pagerEl) pagerEl.innerHTML = '';
    return;
  }
  
  // Render active jobs first, then completed jobs
  const sortedJobs = [...activeJobs, ...completedJobs];
  
  // Calculate pagination
  const totalJobs = sortedJobs.length;
  jobsPaginationState.totalPages = Math.max(1, Math.ceil(totalJobs / jobsPaginationState.pageSize));
  
  // Ensure current page is within bounds - handle edge case of 0 pages
  if (totalJobs === 0) {
    jobsPaginationState.currentPage = 1;
  } else if (jobsPaginationState.currentPage > jobsPaginationState.totalPages) {
    jobsPaginationState.currentPage = jobsPaginationState.totalPages;
  }
  
  // Get jobs for current page
  const startIdx = (jobsPaginationState.currentPage - 1) * jobsPaginationState.pageSize;
  const endIdx = startIdx + jobsPaginationState.pageSize;
  const pageJobs = sortedJobs.slice(startIdx, endIdx);
  
  // Render only jobs on current page
  const cards = pageJobs.map(job => {
    const progress = Math.max(0, Math.min(100, job.progress || 0));
    const steps = job.steps || {};
    const stepsHtml = Object.keys(steps).map(step => renderJobStep(step, steps[step], job.domain)).join('');
    const logsHtml = renderLogEntries(job.logs || []);
    return `
      <div class="job-card">
        <div class="job-summary">
          <div>
            <div>${escapeHtml(job.domain || '')}</div>
            <div class="muted">Started ${fmtTime(job.started)}</div>
            ${job.completed_at ? `<div class="muted">Completed ${fmtTime(job.completed_at)}</div>` : ''}
          </div>
          <div class="job-summary-meta">
            <span class="status-pill ${statusClass(job.status)}">${statusLabel(job.status)}</span>
            <span class="badge">${progress}%</span>
          </div>
        </div>
        ${renderProgress(progress, job.status)}
        <div class="job-meta">
          <span><strong>Wordlist:</strong> ${escapeHtml(job.wordlist || 'default')}</span>
          <span><strong>Interval:</strong> ${escapeHtml(job.interval || 0)}s</span>
          <span><strong>Nikto:</strong> ${job.skip_nikto ? 'Skipped' : 'Enabled'}</span>
        </div>
        <div class="job-message">${escapeHtml(job.message || '')}</div>
        ${renderJobControls(job)}
        <div class="job-steps">
          ${stepsHtml || '<p class="muted">Awaiting step updates…</p>'}
        </div>
        <div class="job-log">
          ${logsHtml}
        </div>
      </div>
    `;
  });
  jobsList.innerHTML = cards.join('');
  
  // Render pagination controls
  renderJobsPagination(totalJobs);
}

function renderJobsPagination(totalJobs) {
  const pagerEl = document.getElementById('jobs-pagination');
  if (!pagerEl) return;
  
  // Don't show pagination if only one page
  if (jobsPaginationState.totalPages <= 1) {
    pagerEl.innerHTML = '';
    return;
  }
  
  const state = jobsPaginationState;
  pagerEl.innerHTML = `
    <span class="page-info">Showing ${(state.currentPage - 1) * state.pageSize + 1}-${Math.min(state.currentPage * state.pageSize, totalJobs)} of ${totalJobs} jobs</span>
    <button data-jobs-page-action="first" ${state.currentPage === 1 ? 'disabled' : ''}>&laquo;</button>
    <button data-jobs-page-action="prev" ${state.currentPage === 1 ? 'disabled' : ''}>&lsaquo;</button>
    <span>Page ${state.currentPage} / ${state.totalPages}</span>
    <button data-jobs-page-action="next" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&rsaquo;</button>
    <button data-jobs-page-action="last" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&raquo;</button>
  `;
}

// Handle jobs pagination clicks
// Note: Using document-level event delegation because pagination buttons are dynamically rendered
document.addEventListener('click', (event) => {
  const btn = event.target.closest('[data-jobs-page-action]');
  if (!btn) return;
  
  const action = btn.getAttribute('data-jobs-page-action');
  if (action === 'prev') {
    jobsPaginationState.currentPage = Math.max(1, jobsPaginationState.currentPage - 1);
  } else if (action === 'next') {
    jobsPaginationState.currentPage = Math.min(jobsPaginationState.totalPages, jobsPaginationState.currentPage + 1);
  } else if (action === 'first') {
    jobsPaginationState.currentPage = 1;
  } else if (action === 'last') {
    jobsPaginationState.currentPage = jobsPaginationState.totalPages;
  }
  
  // Re-render jobs with new page - latestRunningJobs is already filtered/sorted from API
  renderJobs(latestRunningJobs);
});

// Pagination state for queue view
let queuePaginationState = {
  currentPage: 1,
  pageSize: 10,  // Show 10 queued jobs per page
  totalPages: 1
};

function renderQueue(queue) {
  const items = Array.isArray(queue) ? queue : [];
  statQueued.textContent = items.length;
  if (!items.length) {
    queueList.innerHTML = '<div class="section-placeholder">Queue empty.</div>';
    const pagerEl = document.getElementById('queue-pagination');
    if (pagerEl) pagerEl.innerHTML = '';
    return;
  }
  
  // Calculate pagination
  const totalItems = items.length;
  queuePaginationState.totalPages = Math.max(1, Math.ceil(totalItems / queuePaginationState.pageSize));
  
  // Ensure current page is within bounds - handle edge case of 0 pages
  if (totalItems === 0) {
    queuePaginationState.currentPage = 1;
  } else if (queuePaginationState.currentPage > queuePaginationState.totalPages) {
    queuePaginationState.currentPage = queuePaginationState.totalPages;
  }
  
  // Get items for current page
  const startIdx = (queuePaginationState.currentPage - 1) * queuePaginationState.pageSize;
  const endIdx = startIdx + queuePaginationState.pageSize;
  const pageItems = items.slice(startIdx, endIdx);
  
  // Render only items on current page
  const cards = pageItems.map((job) => {
    return `
      <div class="queue-card">
        <div class="queue-row">
          <strong>${escapeHtml(job.domain || '')}</strong>
          <span class="badge">#${escapeHtml(job.position || 0)}</span>
        </div>
        <p class="muted">Queued ${fmtTime(job.queued_at)}</p>
        <div class="queue-meta">
          <span>Wordlist: ${escapeHtml(job.wordlist || 'default')}</span>
          <span>Interval: ${escapeHtml(job.interval || 0)}s</span>
          <span>Nikto: ${job.skip_nikto ? 'Skipped' : 'Enabled'}</span>
        </div>
      </div>
    `;
  }).join('');
  queueList.innerHTML = cards;
  
  // Render pagination controls
  renderQueuePagination(totalItems);
}

function renderQueuePagination(totalItems) {
  const pagerEl = document.getElementById('queue-pagination');
  if (!pagerEl) return;
  
  // Don't show pagination if only one page
  if (queuePaginationState.totalPages <= 1) {
    pagerEl.innerHTML = '';
    return;
  }
  
  const state = queuePaginationState;
  pagerEl.innerHTML = `
    <span class="page-info">Showing ${(state.currentPage - 1) * state.pageSize + 1}-${Math.min(state.currentPage * state.pageSize, totalItems)} of ${totalItems} queued jobs</span>
    <button data-queue-page-action="first" ${state.currentPage === 1 ? 'disabled' : ''}>&laquo;</button>
    <button data-queue-page-action="prev" ${state.currentPage === 1 ? 'disabled' : ''}>&lsaquo;</button>
    <span>Page ${state.currentPage} / ${state.totalPages}</span>
    <button data-queue-page-action="next" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&rsaquo;</button>
    <button data-queue-page-action="last" ${state.currentPage === state.totalPages ? 'disabled' : ''}>&raquo;</button>
  `;
}

// Handle queue pagination clicks
// Note: Using document-level event delegation because pagination buttons are dynamically rendered
document.addEventListener('click', (event) => {
  const btn = event.target.closest('[data-queue-page-action]');
  if (!btn) return;
  
  const action = btn.getAttribute('data-queue-page-action');
  if (action === 'prev') {
    queuePaginationState.currentPage = Math.max(1, queuePaginationState.currentPage - 1);
  } else if (action === 'next') {
    queuePaginationState.currentPage = Math.min(queuePaginationState.totalPages, queuePaginationState.currentPage + 1);
  } else if (action === 'first') {
    queuePaginationState.currentPage = 1;
  } else if (action === 'last') {
    queuePaginationState.currentPage = queuePaginationState.totalPages;
  }
  
  // Re-render queue with new page - latestQueuedJobs is already from API
  renderQueue(latestQueuedJobs);
});

