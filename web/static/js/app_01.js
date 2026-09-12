console.log('[DEBUG] Script loading started');

// Load current user info
async function loadUserInfo() {
  try {
    const resp = await fetch('/api/auth/user');
    const data = await resp.json();
    if (data.success && data.user) {
      const displayName = data.user.username + (data.user.is_admin ? ' (Admin)' : '');
      document.getElementById('username-display').textContent = displayName;
      
      // Show user management tab for admins only
      if (data.user.is_admin) {
        const userMgmtTab = document.getElementById('user-mgmt-tab');
        if (userMgmtTab) {
          userMgmtTab.style.display = 'block';
        }
      }
    }
  } catch (err) {
    console.error('Failed to load user info:', err);
  }
}

// Logout function
async function logout() {
  if (!confirm('Are you sure you want to logout?')) return;
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
    window.location.href = '/login';
  } catch (err) {
    console.error('Logout failed:', err);
    alert('Logout failed. Please try again.');
  }
}

// Load user info on page load
loadUserInfo();

const navLinks = document.querySelectorAll('.nav-link');
const viewSections = document.querySelectorAll('.module');
const SEVERITY_SCALE = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE'];
const SEVERITY_RANK = SEVERITY_SCALE.reduce((acc, label, idx) => {
  acc[label] = idx;
  return acc;
}, {});



function setView(target) {
  const next = target || 'overview';
  viewSections.forEach(section => section.classList.toggle('active', section.dataset.view === next));
  navLinks.forEach(link => link.classList.toggle('active', link.dataset.view === next));
  history.replaceState(null, '', `#${next}`);
  
  // Update logs when switching to logs view
  if (next === 'logs') {
    updateLogsView();
  }
  // Update database viewer when switching to database view
  if (next === 'database' && typeof loadDatabaseView === 'function') {
    loadDatabaseView();
  }
  // Check tool availability the first time the how-to view is opened
  if (next === 'howto' && typeof loadHowtoTools === 'function') {
    loadHowtoTools(false);
  }
}
navLinks.forEach(link => {
  link.addEventListener('click', (event) => {
    event.preventDefault();
    setView(link.dataset.view);
  });
});
const initialView = location.hash ? location.hash.substring(1) : 'overview';
setView(initialView || 'overview');

// Wire up the "How to use this tool" view (function declarations are hoisted)
initHowtoView();

// Settings tabs handler
const settingsTabs = document.querySelectorAll('.settings-tab');
const settingsTabContents = document.querySelectorAll('.settings-subtab-content');
function setSettingsTab(tabName) {
  settingsTabs.forEach(tab => tab.classList.toggle('active', tab.dataset.tab === tabName));
  settingsTabContents.forEach(content => content.classList.toggle('active', content.dataset.tabContent === tabName));
}
settingsTabs.forEach(tab => {
  tab.addEventListener('click', () => setSettingsTab(tab.dataset.tab));
});

const POLL_INTERVAL = 8000;
const MAX_SUBDOMAINS_PREVIEW = 50; // Maximum subdomains to show in overview before "Show more"
const launchForm = document.getElementById('launch-form');
const launchWordlist = document.getElementById('launch-wordlist');
const launchInterval = document.getElementById('launch-interval');
const launchSkipNikto = document.getElementById('launch-skip-nikto');
const launchStatus = document.getElementById('launch-status');
const importForm = document.getElementById('import-form');
const importFile = document.getElementById('import-file');
const importContent = document.getElementById('import-content');
const importSkipNikto = document.getElementById('import-skip-nikto');
const importStatus = document.getElementById('import-status');
const jobsList = document.getElementById('jobs-list');
const queueList = document.getElementById('queue-list');
const targetsList = document.getElementById('targets-list');
const toolsList = document.getElementById('tools-list');
const workersBody = document.getElementById('workers-body');
const reportsBody = document.getElementById('reports-body');
const monitorsList = document.getElementById('monitors-list');
const detailOverlay = document.getElementById('detail-overlay');
const detailContent = document.getElementById('detail-content');
const detailClose = document.getElementById('detail-close');
let latestTargetsData = {};
let latestConfig = {};
const historyCache = {};
const commandHistoryCache = {};
let selectedReportDomain = null;
let latestRunningJobs = [];
let latestQueuedJobs = [];
const settingsForm = document.getElementById('settings-form');
const settingsWordlist = document.getElementById('settings-wordlist');
const settingsInterval = document.getElementById('settings-interval');
const settingsWildcardTlds = document.getElementById('settings-wildcard-tlds');
const settingsSkipNikto = document.getElementById('settings-skip-nikto');
const settingsEnableScreenshots = document.getElementById('settings-enable-screenshots');
const settingsDnsResolvers = document.getElementById('settings-dns-resolvers');
const settingsWordlistFile = document.getElementById('settings-wordlist-file');
const settingsWordlistUpload = document.getElementById('settings-wordlist-upload');
const settingsWordlistStatus = document.getElementById('settings-wordlist-status');

const settingsEnableDnsx = document.getElementById('settings-enable-dnsx');
const settingsEnablePortScan = document.getElementById('settings-enable-port-scan');
const settingsEnableVhostEnum = document.getElementById('settings-enable-vhost-enum');
const settingsEnableJsScan = document.getElementById('settings-enable-js-scan');
const settingsBundledNucleiTemplates = document.getElementById('settings-bundled-nuclei-templates');
const settingsPortScanPorts = document.getElementById('settings-port-scan-ports');
const settingsVhostMaxTargets = document.getElementById('settings-vhost-max-targets');
const settingsGlobalRateLimit = document.getElementById('settings-global-rate-limit');
const settingsMaxJobs = document.getElementById('settings-max-jobs');
const settingsDefaultToolWorkers = document.getElementById('settings-default-tool-workers');
const settingsResetToolSlots = document.getElementById('settings-reset-tool-slots');

if (settingsResetToolSlots) {
  settingsResetToolSlots.addEventListener('click', () => {
    document.querySelectorAll('input[name^="max_parallel_"]').forEach(input => { input.value = 0; });
    settingsFormDirty = true;
    const hint = document.getElementById('settings-tool-slots-hint');
    if (hint) hint.textContent = 'Overrides cleared - save to apply.';
  });
}
const settingsDnsx = document.getElementById('settings-dnsx');
const settingsNmap = document.getElementById('settings-nmap');
const settingsHttpx = document.getElementById('settings-httpx');
const settingsFFUF = document.getElementById('settings-ffuf');
const settingsNuclei = document.getElementById('settings-nuclei');
const settingsNikto = document.getElementById('settings-nikto');
const settingsGowitness = document.getElementById('settings-gowitness');
const settingsDynamicMode = document.getElementById('settings-dynamic-mode');
const settingsDynamicBaseJobs = document.getElementById('settings-dynamic-base-jobs');
const settingsDynamicMaxJobs = document.getElementById('settings-dynamic-max-jobs');
const settingsDynamicCpuThreshold = document.getElementById('settings-dynamic-cpu-threshold');
const settingsDynamicMemoryThreshold = document.getElementById('settings-dynamic-memory-threshold');
const settingsAutoBackupEnabled = document.getElementById('settings-auto-backup-enabled');
const settingsAutoBackupInterval = document.getElementById('settings-auto-backup-interval');
const settingsAutoBackupMaxCount = document.getElementById('settings-auto-backup-max-count');
const backupNameInput = document.getElementById('backup-name-input');
const createBackupBtn = document.getElementById('create-backup-btn');
const backupList = document.getElementById('backup-list');
const settingsStatus = document.getElementById('settings-status');
const settingsSummary = document.getElementById('settings-summary');
const settingsSaveBtn = document.querySelector('#settings-form button[type="submit"]');
console.log('[DEBUG] All DOM elements retrieved, settingsForm:', settingsForm ? 'found' : 'NULL', 'saveBtn:', settingsSaveBtn ? 'found' : 'NULL');
const templateInputs = {
  nmap: document.getElementById('template-nmap'),
  dnsx: document.getElementById('template-dnsx'),
  ffuf: document.getElementById('template-ffuf'),
  httpx: document.getElementById('template-httpx'),
  nuclei: document.getElementById('template-nuclei'),
  nikto: document.getElementById('template-nikto'),
  gowitness: document.getElementById('template-gowitness'),
};
const monitorForm = document.getElementById('monitor-form');
const monitorName = document.getElementById('monitor-name');
const monitorUrl = document.getElementById('monitor-url');
const monitorInterval = document.getElementById('monitor-interval');
const monitorStatus = document.getElementById('monitor-status');
const statActive = document.getElementById('stat-active');
const statQueued = document.getElementById('stat-queued');
const statTargets = document.getElementById('stat-targets');
const statSubs = document.getElementById('stat-subdomains');
const overviewTargetsList = document.getElementById('overview-targets-list');
let launchFormDirty = false;
let settingsFormDirty = false;
let monitorsData = [];
let allLogs = [];
let filteredLogs = [];
const logsTable = document.getElementById('logs-table');
const logsTbody = document.getElementById('logs-tbody');
const logsPagination = document.getElementById('logs-pagination');
const logsCount = document.getElementById('logs-count');
const logSearch = document.getElementById('log-search');
const logSourceFilter = document.getElementById('log-source-filter');
const logLevelFilter = document.getElementById('log-level-filter');
const logClearFilters = document.getElementById('log-clear-filters');
const STEP_SEQUENCE = [
  { flag: 'dnsx_done', label: 'DNSx' },
  { flag: 'port_scan_done', label: 'Port scan' },
  { flag: 'httpx_done', label: 'httpx' },
  { flag: 'vhost_enum_done', label: 'vhost' },
  { flag: 'screenshots_done', label: 'Screenshots', skipWhen: () => latestConfig.enable_screenshots === false },
  { flag: 'nuclei_done', label: 'Nuclei' },
  { flag: 'js_scan_done', label: 'JS Scan', skipWhen: () => latestConfig.enable_js_scan === false },
  { flag: 'nikto_done', label: 'Nikto', skipWhen: (info) => shouldSkipNikto(info) },
];
const DEFAULT_PAGE_SIZE = 50;

const STATUS_LABELS = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  completed_with_errors: 'Completed w/ warnings',
  failed: 'Failed',
  error: 'Error',
  dispatched: 'Dispatched',
  skipped: 'Skipped',
  pending: 'Pending',
  paused: 'Paused',
  pausing: 'Pausing'
};

function statusLabel(value) {
  if (!value) return 'Unknown';
  return STATUS_LABELS[value] || value.replace(/_/g, ' ');
}

function statusClass(value) {
  switch (value) {
    case 'completed':
      return 'status-completed';
    case 'completed_with_errors':
    case 'error':
    case 'failed':
      return 'status-error';
    case 'running':
    case 'queued':
    case 'dispatched':
      return 'status-running';
    case 'paused':
    case 'pausing':
      return 'status-paused';
    case 'skipped':
    case 'pending':
    default:
      return 'status-skipped';
  }
}

function escapeHtml(value) {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// User management functions
async function loadUsers() {
  try {
    const resp = await fetch('/api/users');
    const data = await resp.json();
    if (data.success) {
      displayUsers(data.users);
    } else {
      document.getElementById('users-list').innerHTML = `<p class="muted">${escapeHtml(data.message || 'Failed to load users')}</p>`;
    }
  } catch (err) {
    console.error('Failed to load users:', err);
    document.getElementById('users-list').innerHTML = '<p class="muted">Failed to load users</p>';
  }
}

function displayUsers(users) {
  const listEl = document.getElementById('users-list');
  if (!users || users.length === 0) {
    listEl.innerHTML = '<p class="muted">No users found</p>';
    return;
  }
  
  const html = users.map(user => `
    <div style="padding: 12px; border: 1px solid #1e293b; border-radius: 6px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
      <div>
        <strong>${escapeHtml(user.username)}</strong>
        ${user.is_admin ? '<span class="badge" style="background: #3b82f6;">Admin</span>' : ''}
        <div class="muted" style="font-size: 12px; margin-top: 4px;">Created: ${fmtTime(user.created_at)}</div>
      </div>
      <div style="display: flex; gap: 8px;">
        <button onclick="editUser(${user.id}, '${escapeHtml(user.username)}', ${user.is_admin})" style="padding: 6px 12px; background: #3b82f6; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">Edit</button>
        <button onclick="deleteUser(${user.id}, '${escapeHtml(user.username)}')" style="padding: 6px 12px; background: #dc2626; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">Delete</button>
      </div>
    </div>
  `).join('');
  
  listEl.innerHTML = html;
}

async function editUser(userId, username, isAdmin) {
  const newUsername = prompt('Enter new username (leave empty to keep current):', username);
  if (newUsername === null) return; // Cancelled
  
  const newPassword = prompt('Enter new password (leave empty to keep current):');
  if (newPassword === null) return; // Cancelled
  
  const changeAdmin = confirm(`Current admin status: ${isAdmin ? 'Admin' : 'Regular user'}.\n\nClick OK to toggle admin status, or Cancel to keep current.`);
  
  const payload = { user_id: userId };
  if (newUsername && newUsername.trim() !== username) {
    payload.username = newUsername.trim();
  }
  if (newPassword && newPassword.trim()) {
    payload.password = newPassword.trim();
  }
  if (changeAdmin) {
    payload.is_admin = !isAdmin;
  }
  
  // Check if any changes were made
  if (!payload.username && !payload.password && !('is_admin' in payload)) {
    alert('No changes specified');
    return;
  }
  
  try {
    const resp = await fetch('/api/users/edit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    
    const data = await resp.json();
    if (data.success) {
      alert(data.message);
      loadUsers();
    } else {
      alert('Error: ' + (data.message || 'Failed to update user'));
    }
  } catch (err) {
    console.error('Failed to update user:', err);
    alert('An error occurred while updating the user');
  }
}

async function deleteUser(userId, username) {
  if (!confirm(`Are you sure you want to delete user '${username}'?\n\nThis action cannot be undone.`)) {
    return;
  }
  
  try {
    const resp = await fetch('/api/users/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: userId })
    });
    
    const data = await resp.json();
    if (data.success) {
      alert(data.message);
      loadUsers();
    } else {
      alert('Error: ' + (data.message || 'Failed to delete user'));
    }
  } catch (err) {
    console.error('Failed to delete user:', err);
    alert('An error occurred while deleting the user');
  }
}

// Create user form handler
const createUserForm = document.getElementById('create-user-form');
if (createUserForm) {
  createUserForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const statusEl = document.getElementById('create-user-status');
    statusEl.textContent = '';
    statusEl.className = 'status';
    
    const username = document.getElementById('new-username').value.trim();
    const password = document.getElementById('new-password').value;
    const passwordConfirm = document.getElementById('new-password-confirm').value;
    const isAdmin = document.getElementById('new-user-admin').checked;
    
    if (!username || !password) {
      statusEl.textContent = 'Username and password are required';
      statusEl.className = 'status error';
      return;
    }
    
    if (password !== passwordConfirm) {
      statusEl.textContent = 'Passwords do not match';
      statusEl.className = 'status error';
      return;
    }
    
    try {
      const resp = await fetch('/api/users/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, is_admin: isAdmin })
      });
      
      const data = await resp.json();
      if (data.success) {
        statusEl.textContent = data.message;
        statusEl.className = 'status success';
        createUserForm.reset();
        // Reload users list
        loadUsers();
      } else {
        statusEl.textContent = data.message || 'Failed to create user';
        statusEl.className = 'status error';
      }
    } catch (err) {
      console.error('Failed to create user:', err);
      statusEl.textContent = 'An error occurred';
      statusEl.className = 'status error';
    }
  });
}

// Load users when switching to users tab
const userMgmtTab = document.querySelector('[data-tab="users"]');
if (userMgmtTab) {
  userMgmtTab.addEventListener('click', () => {
    loadUsers();
  });
}

