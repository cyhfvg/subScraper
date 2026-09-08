function saveCheckboxState(id, checked) {
  try {
    localStorage.setItem(`checkbox_${id}`, checked ? '1' : '0');
  } catch (e) {
    // Ignore
  }
}

function loadCheckboxState(id, defaultValue = false) {
  try {
    const saved = localStorage.getItem(`checkbox_${id}`);
    if (saved === null) return defaultValue;
    return saved === '1' ? true : false;
  } catch (e) {
    return defaultValue;
  }
}

// Apply to all checkboxes on page
document.querySelectorAll('input[type="checkbox"][id]').forEach(checkbox => {
  const savedState = loadCheckboxState(checkbox.id);
  if (savedState !== null) {
    checkbox.checked = savedState;
  }
  checkbox.addEventListener('change', () => {
    saveCheckboxState(checkbox.id, checkbox.checked);
  });
});

// Enhance attachSubdomainFilters to persist state
const originalAttachSubdomainFilters = attachSubdomainFilters;
attachSubdomainFilters = function(detailEl) {
  originalAttachSubdomainFilters(detailEl);
  
  // Load saved filter state if available
  const domain = detailEl.querySelector('[data-domain]')?.getAttribute('data-domain');
  if (domain) {
    const saved = loadReportFilters(domain);
    if (saved) {
      const statusGroup = detailEl.querySelector('[data-status-filter]');
      const searchInput = detailEl.querySelector('[data-sub-search]');
      
      if (saved.statusFilters && statusGroup) {
        statusGroup.querySelectorAll('input[type="checkbox"]').forEach(cb => {
          if (saved.statusFilters.includes(cb.value)) {
            cb.checked = true;
          } else {
            cb.checked = false;
          }
        });
      }
      
      if (saved.searchQuery && searchInput) {
        searchInput.value = saved.searchQuery;
      }
    }
  }
  
  // Save on change
  const statusGroup = detailEl.querySelector('[data-status-filter]');
  const searchInput = detailEl.querySelector('[data-sub-search]');
  
  const saveFilters = () => {
    if (domain) {
      const statusFilters = statusGroup 
        ? Array.from(statusGroup.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value)
        : [];
      const searchQuery = searchInput ? searchInput.value : '';
      saveReportFilters(domain, { statusFilters, searchQuery });
    }
  };
  
  if (statusGroup) {
    statusGroup.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', saveFilters);
    });
  }
  if (searchInput) {
    searchInput.addEventListener('input', saveFilters);
  }
};

console.log('[DEBUG] Script execution complete, starting event handlers and fetch');
renderWorkflowDiagram();
fetchState();

// Only auto-refresh on overview/monitoring pages, not on detail pages
// This prevents unnecessary refreshes on static pages like settings, gallery, etc.
const VIEWS_WITH_AUTO_REFRESH = ['overview', 'jobs', 'queue', 'workers', 'resources', 'monitors', 'logs'];
let pollIntervalId = null;

function startPolling() {
  if (pollIntervalId) return; // Already polling
  pollIntervalId = setInterval(() => {
    const currentView = getCurrentView();
    if (VIEWS_WITH_AUTO_REFRESH.includes(currentView)) {
      fetchState();
    }
  }, POLL_INTERVAL);
}

function getCurrentView() {
  const hash = location.hash ? location.hash.substring(1) : 'overview';
  return hash || 'overview';
}

// Start polling
startPolling();

// Also fetch when view changes to ensure fresh data
window.addEventListener('hashchange', () => {
  const currentView = getCurrentView();
  if (VIEWS_WITH_AUTO_REFRESH.includes(currentView)) {
    fetchState();
  }
});

// ================== DATABASE VIEWER ==================
(function () {
  let dbCurrentTable = '';
  let dbCurrentPage = 1;
  let dbPageSize = 50;
  let dbSortCol = '';
  let dbSortDir = 'asc';
  let dbSearchTerm = '';
  let dbTotalPages = 1;
  let dbTotal = 0;
  let dbColumns = [];

  const dbTableSelect = document.getElementById('db-table-select');
  const dbSearch = document.getElementById('db-search');
  const dbPageSizeSelect = document.getElementById('db-page-size');
  const dbRefreshBtn = document.getElementById('db-refresh-btn');
  const dbStatus = document.getElementById('db-status');
  const dbThead = document.getElementById('db-thead');
  const dbTbody = document.getElementById('db-tbody');
  const dbPagination = document.getElementById('db-pagination');

  async function loadDbTables() {
    try {
      const resp = await fetch('/api/db/tables');
      const data = await resp.json();
      if (!data.success) { dbStatus.textContent = data.message || 'Failed to load tables.'; return; }
      const prevVal = dbTableSelect ? dbTableSelect.value : '';
      dbTableSelect.innerHTML = '<option value="">— select a table —</option>' +
        data.tables.map(t => `<option value="${escapeHtml(t.name)}">${escapeHtml(t.name)} (${t.row_count})</option>`).join('');
      // Restore previous selection if it still exists
      if (prevVal && dbTableSelect.querySelector(`option[value="${escapeHtml(prevVal)}"]`)) {
        dbTableSelect.value = prevVal;
      }
    } catch (err) {
      dbStatus.textContent = 'Error loading tables: ' + err.message;
    }
  }

  async function loadDbTable() {
    if (!dbCurrentTable) {
      dbThead.innerHTML = '<tr><th>Select a table above</th></tr>';
      dbTbody.innerHTML = '<tr><td class="muted">No table selected.</td></tr>';
      dbPagination.innerHTML = '';
      dbStatus.textContent = '';
      return;
    }
    dbStatus.textContent = 'Loading\u2026';
    try {
      const params = new URLSearchParams({
        page: dbCurrentPage,
        page_size: dbPageSize,
        search: dbSearchTerm,
        sort_col: dbSortCol,
        sort_dir: dbSortDir,
      });
      const resp = await fetch(`/api/db/table/${encodeURIComponent(dbCurrentTable)}?${params}`);
      const data = await resp.json();
      if (!data.success) { dbStatus.textContent = data.message || 'Failed to load table data.'; return; }
      dbColumns = data.columns || [];
      dbTotalPages = data.total_pages || 1;
      dbTotal = data.total || 0;
      renderDbTable(data.rows || []);
      renderDbPagination();
      dbStatus.textContent = `${dbTotal} row${dbTotal !== 1 ? 's' : ''} total \u2014 page ${dbCurrentPage} of ${dbTotalPages}`;
    } catch (err) {
      dbStatus.textContent = 'Error: ' + err.message;
    }
  }

  function renderDbTable(rows) {
    if (!dbThead || !dbTbody) return;
    if (dbColumns.length === 0) {
      dbThead.innerHTML = '<tr><th>No columns</th></tr>';
      dbTbody.innerHTML = '<tr><td class="muted">Empty table.</td></tr>';
      return;
    }
    const headerCells = dbColumns.map(col => {
      const isActive = dbSortCol === col;
      const arrow = isActive ? (dbSortDir === 'asc' ? ' \u25b2' : ' \u25bc') : '';
      return `<th style="cursor:pointer;white-space:nowrap;" data-sort-col="${escapeHtml(col)}">${escapeHtml(col)}${arrow}</th>`;
    }).join('');
    dbThead.innerHTML = `<tr>${headerCells}</tr>`;
    dbThead.querySelectorAll('th[data-sort-col]').forEach(th => {
      th.addEventListener('click', () => {
        const col = th.getAttribute('data-sort-col');
        if (dbSortCol === col) {
          dbSortDir = dbSortDir === 'asc' ? 'desc' : 'asc';
        } else {
          dbSortCol = col;
          dbSortDir = 'asc';
        }
        dbCurrentPage = 1;
        loadDbTable();
      });
    });
    if (rows.length === 0) {
      dbTbody.innerHTML = `<tr><td colspan="${dbColumns.length}" class="muted">No rows match your search.</td></tr>`;
      return;
    }
    dbTbody.innerHTML = rows.map(row => {
      const cells = row.map(cell => {
        const text = cell === null ? '<span class="muted">NULL</span>' : escapeHtml(String(cell));
        const title = cell === null ? '' : escapeHtml(String(cell));
        return `<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${title}">${text}</td>`;
      }).join('');
      return `<tr>${cells}</tr>`;
    }).join('');
  }

  function renderDbPagination() {
    if (!dbPagination) return;
    if (dbTotalPages <= 1) { dbPagination.innerHTML = ''; return; }
    dbPagination.innerHTML = `
      <button ${dbCurrentPage === 1 ? 'disabled' : ''} id="db-pg-first">&laquo; First</button>
      <button ${dbCurrentPage === 1 ? 'disabled' : ''} id="db-pg-prev">&lsaquo; Prev</button>
      <span>Page <strong>${dbCurrentPage}</strong> / ${dbTotalPages}</span>
      <button ${dbCurrentPage === dbTotalPages ? 'disabled' : ''} id="db-pg-next">Next &rsaquo;</button>
      <button ${dbCurrentPage === dbTotalPages ? 'disabled' : ''} id="db-pg-last">Last &raquo;</button>
    `;
    dbPagination.querySelector('#db-pg-first')?.addEventListener('click', () => { dbCurrentPage = 1; loadDbTable(); });
    dbPagination.querySelector('#db-pg-prev')?.addEventListener('click', () => { dbCurrentPage = Math.max(1, dbCurrentPage - 1); loadDbTable(); });
    dbPagination.querySelector('#db-pg-next')?.addEventListener('click', () => { dbCurrentPage = Math.min(dbTotalPages, dbCurrentPage + 1); loadDbTable(); });
    dbPagination.querySelector('#db-pg-last')?.addEventListener('click', () => { dbCurrentPage = dbTotalPages; loadDbTable(); });
  }

  if (dbTableSelect) {
    dbTableSelect.addEventListener('change', () => {
      dbCurrentTable = dbTableSelect.value;
      dbCurrentPage = 1;
      dbSortCol = '';
      dbSortDir = 'asc';
      dbSearchTerm = dbSearch ? dbSearch.value.trim() : '';
      loadDbTable();
    });
  }

  let dbSearchTimer = null;
  if (dbSearch) {
    dbSearch.addEventListener('input', () => {
      clearTimeout(dbSearchTimer);
      dbSearchTimer = setTimeout(() => {
        dbSearchTerm = dbSearch.value.trim();
        dbCurrentPage = 1;
        loadDbTable();
      }, 350);
    });
  }

  if (dbPageSizeSelect) {
    dbPageSizeSelect.addEventListener('change', () => {
      dbPageSize = parseInt(dbPageSizeSelect.value, 10) || 50;
      dbCurrentPage = 1;
      loadDbTable();
    });
  }

  if (dbRefreshBtn) {
    dbRefreshBtn.addEventListener('click', () => {
      loadDbTables();
      loadDbTable();
    });
  }

  // Expose function so setView() can trigger it
  window.loadDatabaseView = function () {
    loadDbTables();
    if (dbCurrentTable) loadDbTable();
  };

  // Also load immediately if hash is already #database on page load
  if (getCurrentView() === 'database') {
    loadDbTables();
  }
})();
// ================== END DATABASE VIEWER ==================
