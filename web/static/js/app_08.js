function attachSubdomainFilters(detailEl) {
  const table = detailEl.querySelector('#subdomains-table');
  if (!table) return;
  const statusGroup = detailEl.querySelector('[data-status-filter]');
  const searchInput = detailEl.querySelector('[data-sub-search]');
  const apply = () => {
    const activeStatuses = statusGroup
      ? Array.from(statusGroup.querySelectorAll('input[type="checkbox"]'))
          .filter(input => input.checked)
          .map(input => input.value)
      : [];
    const allowed = activeStatuses.length ? new Set(activeStatuses) : null;
    const query = (searchInput && searchInput.value || '').trim().toLowerCase();
    const rows = table.tBodies[0] ? Array.from(table.tBodies[0].rows) : [];
    rows.forEach(row => {
      const status = row.dataset.statusCode || 'none';
      const host = row.dataset.host || '';
      const title = row.dataset.title || '';
      const matchesStatus = !allowed || allowed.has(status);
      const matchesSearch = !query || host.includes(query) || title.includes(query);
      row.dataset.filterHidden = matchesStatus && matchesSearch ? 'false' : 'true';
    });
    refreshPagination(table);
  };
  if (statusGroup) {
    statusGroup.querySelectorAll('input[type="checkbox"]').forEach(input => input.addEventListener('change', apply));
  }
  if (searchInput) {
    searchInput.addEventListener('input', apply);
  }
  apply();
}

function attachSeverityFilter(wrapper, table) {
  if (!wrapper || !table) return;
  const checkboxes = wrapper.querySelectorAll('input[type="checkbox"]');
  if (!checkboxes.length) return;
  
  // Generate a unique ID for this filter set based on table ID and wrapper attributes
  const tableId = table.id || '';
  const filterId = `severity_filter_${tableId}`;
  
  // Restore saved checkbox states
  checkboxes.forEach((cb, index) => {
    const cbId = `${filterId}_${cb.value}_${index}`;
    const saved = loadCheckboxState(cbId);
    if (saved !== null) {
      cb.checked = saved;
    }
  });
  
  const apply = () => {
    const allowed = new Set(Array.from(checkboxes).filter(cb => cb.checked).map(cb => cb.value));
    const rows = table.tBodies[0] ? Array.from(table.tBodies[0].rows) : [];
    rows.forEach(row => {
      const sev = row.dataset.severity || 'INFO';
      row.dataset.filterHidden = allowed.has(sev) ? 'false' : 'true';
    });
    refreshPagination(table);
  };
  
  checkboxes.forEach((cb, index) => {
    const cbId = `${filterId}_${cb.value}_${index}`;
    cb.addEventListener('change', () => {
      saveCheckboxState(cbId, cb.checked);
      apply();
    });
  });
  
  apply();
}

function attachEndpointFilter(detailEl) {
  const table = detailEl.querySelector('#endpoints-table');
  if (!table) return;
  const searchInput = detailEl.querySelector('[data-endpoint-search]');
  if (!searchInput) return;
  
  const apply = () => {
    const query = (searchInput.value || '').trim().toLowerCase();
    const rows = table.tBodies[0] ? Array.from(table.tBodies[0].rows) : [];
    rows.forEach(row => {
      const endpoint = row.dataset.endpoint || '';
      const matchesSearch = !query || endpoint.includes(query);
      row.dataset.filterHidden = matchesSearch ? 'false' : 'true';
    });
    refreshPagination(table);
  };
  
  searchInput.addEventListener('input', apply);
  apply();
}

async function fetchCommandHistory(domain) {
  if (commandHistoryCache[domain]) {
    return commandHistoryCache[domain];
  }
  try {
    const resp = await fetch(`/api/history/commands?domain=${encodeURIComponent(domain)}&limit=400`);
    if (!resp.ok) throw new Error('Failed to fetch commands');
    const data = await resp.json();
    const commands = Array.isArray(data.commands) ? data.commands : [];
    commandHistoryCache[domain] = commands;
    return commands;
  } catch (err) {
    return [];
  }
}

async function hydrateCommandLog(domain) {
  const container = document.querySelector('[data-command-log]');
  if (!container) return;
  const targetDomain = container.getAttribute('data-command-domain');
  if (targetDomain !== domain) return;
  container.innerHTML = '<p class="muted">Loading command history…</p>';
  const commands = await fetchCommandHistory(domain);
  if (container.getAttribute('data-command-domain') !== domain) {
    return;
  }
  if (!commands.length) {
    container.innerHTML = '<p class="muted">No commands recorded yet.</p>';
    return;
  }
  const items = commands.map(entry => `
    <li class="command-item">
      <span class="command-time">${escapeHtml(entry.ts || '')}</span>
      <span class="command-text">${escapeHtml(entry.text || '')}</span>
    </li>
  `).join('');
  container.innerHTML = `<ul class="command-list">${items}</ul>`;
}

async function handleResumeTarget(domain, button) {
  if (!domain || !button) return;
  const original = button.textContent;
  button.disabled = true;
  button.textContent = 'Resuming…';
  try {
    const resp = await fetch('/api/targets/resume', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    const data = await resp.json();
    button.textContent = data.message || original;
    if (data.success) {
      fetchState();
    }
  } catch (err) {
    button.textContent = err.message || 'Failed';
  } finally {
    setTimeout(() => {
      button.textContent = original;
      button.disabled = false;
    }, 2000);
  }
}

async function handleJobControl(action, domain, button) {
  if (!domain || !button) return;
  const original = button.textContent;
  button.disabled = true;
  button.textContent = action === 'pause' ? 'Pausing…' : 'Resuming…';
  try {
    const resp = await fetch(`/api/jobs/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    const data = await resp.json();
    button.textContent = data.message || original;
    if (data.success) {
      fetchState();
    }
  } catch (err) {
    button.textContent = err.message || 'Failed';
  } finally {
    setTimeout(() => {
      button.textContent = original;
      button.disabled = false;
    }, 2000);
  }
}

reportsBody.addEventListener('click', (event) => {
  const subBtn = event.target.closest('.sub-link');
  if (subBtn) {
    event.preventDefault();
    const domain = subBtn.getAttribute('data-domain');
    const sub = subBtn.getAttribute('data-sub');
    openSubdomainDetail(domain, sub);
    return;
  }
  const resumeBtn = event.target.closest('[data-resume-target]');
  if (resumeBtn) {
    const domain = resumeBtn.getAttribute('data-resume-target');
    handleResumeTarget(domain, resumeBtn);
    return;
  }
  const card = event.target.closest('.report-nav-card');
  if (card) {
    const domain = card.getAttribute('data-report-domain');
    if (domain) {
      renderReportDetail(domain);
    }
  }
});

jobsList.addEventListener('click', (event) => {
  const pauseBtn = event.target.closest('[data-pause-job]');
  if (pauseBtn) {
    const domain = pauseBtn.getAttribute('data-pause-job');
    handleJobControl('pause', domain, pauseBtn);
    return;
  }
  const resumeBtn = event.target.closest('[data-resume-job]');
  if (resumeBtn) {
    const domain = resumeBtn.getAttribute('data-resume-job');
    handleJobControl('resume', domain, resumeBtn);
    return;
  }
  const skipBtn = event.target.closest('[data-skip-step]');
  if (skipBtn) {
    const domain = skipBtn.getAttribute('data-skip-step');
    const step = skipBtn.getAttribute('data-step-name');
    handleSkipStep(domain, step, skipBtn);
  }
});

// Resume All button handler
const resumeAllBtn = document.getElementById('resume-all-btn');
if (resumeAllBtn) {
  resumeAllBtn.addEventListener('click', async () => {
    const original = resumeAllBtn.textContent;
    resumeAllBtn.disabled = true;
    resumeAllBtn.textContent = 'Resuming...';
    try {
      const resp = await fetch('/api/jobs/resume-all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await resp.json();
      resumeAllBtn.textContent = data.message || 'Done';
      if (data.success) {
        fetchState();
      }
    } catch (err) {
      resumeAllBtn.textContent = err.message || 'Failed';
    } finally {
      setTimeout(() => {
        resumeAllBtn.textContent = original;
        resumeAllBtn.disabled = false;
      }, 2000);
    }
  });
}

// Cancel All button handler
const cancelAllBtn = document.getElementById('cancel-all-btn');
if (cancelAllBtn) {
  cancelAllBtn.addEventListener('click', async () => {
    if (!confirm('Cancel all running jobs? They will be paused and can be resumed later.')) {
      return;
    }
    const original = cancelAllBtn.textContent;
    cancelAllBtn.disabled = true;
    cancelAllBtn.textContent = 'Cancelling...';
    try {
      const resp = await fetch('/api/jobs/cancel-all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await resp.json();
      cancelAllBtn.textContent = data.message || 'Done';
      if (data.success) {
        fetchState();
      }
    } catch (err) {
      cancelAllBtn.textContent = err.message || 'Failed';
    } finally {
      setTimeout(() => {
        cancelAllBtn.textContent = original;
        cancelAllBtn.disabled = false;
      }, 2000);
    }
  });
}

async function handleSkipStep(domain, step, btn) {
  if (!confirm(`Skip ${step.toUpperCase()} step for ${domain}? This will mark it as done without running.`)) {
    return;
  }
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Skipping...';
  try {
    const resp = await fetch('/api/jobs/skip-step', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, step })
    });
    const data = await resp.json();
    if (data.success) {
      btn.textContent = 'Skipped';
      fetchState();
    } else {
      btn.textContent = 'Failed';
      alert(data.message || 'Failed to skip step');
    }
  } catch (err) {
    btn.textContent = 'Error';
    alert(err.message || 'Failed to skip step');
  } finally {
    setTimeout(() => {
      btn.textContent = original;
      btn.disabled = false;
    }, 2000);
  }
}


document.addEventListener('click', (event) => {
  const header = event.target.closest('.collapsible-header');
  if (!header) return;
  const container = header.closest('.collapsible');
  if (!container) return;
  container.classList.toggle('open');
  const body = container.querySelector('.collapsible-body');
  if (!body) return;
  if (!container.classList.contains('open')) {
    body.scrollTop = 0;
  }
  
  // Save collapsible state to localStorage
  const collapsibleId = container.getAttribute('data-collapsible');
  if (collapsibleId) {
    saveCollapsibleState(collapsibleId, container.classList.contains('open'));
  }
});

// Functions to manage collapsible state
function saveCollapsibleState(id, isOpen) {
  try {
    localStorage.setItem(`collapsible_${id}`, isOpen ? '1' : '0');
  } catch (e) {
    // Ignore localStorage errors
  }
}

function loadCollapsibleState(id) {
  try {
    const saved = localStorage.getItem(`collapsible_${id}`);
    return saved === '1';
  } catch (e) {
    return false;
  }
}

function restoreAllCollapsibleStates() {
  const collapsibles = document.querySelectorAll('.collapsible[data-collapsible]');
  collapsibles.forEach(container => {
    const id = container.getAttribute('data-collapsible');
    if (id && loadCollapsibleState(id)) {
      container.classList.add('open');
    }
  });
}
// Effective worker count for a tool: its own slot setting, or the global
// "workers per tool" value when that slot is left at 0 (inherit).
function toolSlots(config, tool) {
  const own = config[`max_parallel_${tool}`];
  const fallback = config.default_tool_workers || 5;
  if (own === undefined || own === null || own === '' || Number(own) === 0) {
    return `${fallback} (default)`;
  }
  return own;
}

function renderSettings(config, tools) {
  settingsSummary.innerHTML = `
    <div class="paths-grid">
      <div><strong>Results directory</strong><br><code>${escapeHtml(config.data_dir || '')}</code></div>
      <div><strong>state.json</strong><br><code>${escapeHtml(config.state_file || '')}</code></div>
      <div><strong>dashboard.html</strong><br><code>${escapeHtml(config.dashboard_file || '')}</code></div>
      <div><strong>screenshots</strong><br><code>${escapeHtml(config.screenshots_dir || '')}</code></div>
      <div><strong>Concurrency</strong><br>
        Jobs: ${escapeHtml(config.max_running_jobs || 1)} ·
        Workers per tool: ${escapeHtml(config.default_tool_workers || 5)} ·
        ffuf: ${escapeHtml(toolSlots(config, 'ffuf'))} ·
        nuclei: ${escapeHtml(toolSlots(config, 'nuclei'))} ·
        Nikto: ${escapeHtml(toolSlots(config, 'nikto'))} ·
        Screenshots: ${escapeHtml(toolSlots(config, 'gowitness'))}
      </div>
      <div><strong>Enumerators</strong><br>
        Amass: ${config.enable_amass === false ? 'disabled' : `enabled (timeout=${escapeHtml(config.amass_timeout || 600)}s)`} ·
        Subfinder: ${config.enable_subfinder === false ? 'disabled' : `enabled (t=${escapeHtml(config.subfinder_threads || 32)})`} ·
        Assetfinder: ${config.enable_assetfinder === false ? 'disabled' : `enabled (t=${escapeHtml(config.assetfinder_threads || 10)})`} ·
        Findomain: ${config.enable_findomain === false ? 'disabled' : `enabled (t=${escapeHtml(config.findomain_threads || 40)})`} ·
        Sublist3r: ${config.enable_sublist3r === false ? 'disabled' : 'enabled'} ·
        Screenshots: ${config.enable_screenshots === false ? 'disabled' : 'enabled'}
      </div>
    </div>
  `;
  const toolItems = Object.keys(tools || {}).sort().map(name => {
    const path = tools[name];
    const pill = path ? '<span class="status-pill status-completed">Found</span>' : '<span class="status-pill status-error">Missing</span>';
    const extra = path ? `<code>${escapeHtml(path)}</code>` : '';
    return `<li><span>${escapeHtml(name)}</span><span class="tool-status">${pill} ${extra}</span></li>`;
  }).join('') || '<li class="muted">No tool data.</li>';
  toolsList.innerHTML = toolItems;

  if (!settingsFormDirty) {
    settingsWordlist.value = config.default_wordlist || '';
    settingsInterval.value = config.default_interval || 30;
    settingsWildcardTlds.value = (config.wildcard_tlds || []).join(', ');
    settingsSkipNikto.checked = !!config.skip_nikto_by_default;
    settingsEnableScreenshots.checked = config.enable_screenshots !== false;
    settingsEnableAmass.checked = config.enable_amass !== false;
    settingsAmassTimeout.value = config.amass_timeout || 600;
    if (settingsDnsResolvers) settingsDnsResolvers.value = (config.dns_resolvers || []).join(', ');

    settingsEnableSubfinder.checked = config.enable_subfinder !== false;
    settingsEnableAssetfinder.checked = config.enable_assetfinder !== false;
    settingsEnableFindomain.checked = config.enable_findomain !== false;
    settingsEnableSublist3r.checked = config.enable_sublist3r !== false;
    settingsEnableCrtsh.checked = config.enable_crtsh !== false;
    settingsEnableGithubSubdomains.checked = config.enable_github_subdomains !== false;
    settingsEnableDnsx.checked = config.enable_dnsx !== false;
    settingsEnableWaybackurls.checked = config.enable_waybackurls !== false;
    settingsEnableGau.checked = config.enable_gau !== false;
    if (settingsEnableJsScan) settingsEnableJsScan.checked = config.enable_js_scan !== false;
    if (settingsBundledNucleiTemplates) settingsBundledNucleiTemplates.checked = config.use_bundled_nuclei_templates !== false;
    settingsSubfinderThreads.value = config.subfinder_threads || 32;
    settingsAssetfinderThreads.value = config.assetfinder_threads || 10;
    settingsFindomainThreads.value = config.findomain_threads || 40;
    settingsGlobalRateLimit.value = config.global_rate_limit || 0;
    settingsMaxJobs.value = config.max_running_jobs || 1;
    if (settingsDefaultToolWorkers) settingsDefaultToolWorkers.value = config.default_tool_workers || 5;
    settingsAmass.value = config.max_parallel_amass ?? 0;
    settingsSubfinder.value = config.max_parallel_subfinder ?? 0;
    settingsAssetfinder.value = config.max_parallel_assetfinder ?? 0;
    settingsFindomain.value = config.max_parallel_findomain ?? 0;
    settingsSublist3r.value = config.max_parallel_sublist3r ?? 0;
    settingsCrtsh.value = config.max_parallel_crtsh ?? 0;
    settingsGithubSubdomains.value = config.max_parallel_github_subdomains ?? 0;
    settingsDnsx.value = config.max_parallel_dnsx ?? 0;
    settingsHttpx.value = config.max_parallel_httpx ?? 0;
    settingsFFUF.value = config.max_parallel_ffuf ?? 0;
    settingsWaybackurls.value = config.max_parallel_waybackurls ?? 0;
    settingsGau.value = config.max_parallel_gau ?? 0;
    settingsNuclei.value = config.max_parallel_nuclei ?? 0;
    settingsNikto.value = config.max_parallel_nikto ?? 0;
    settingsGowitness.value = config.max_parallel_gowitness ?? 0;
    settingsDynamicMode.checked = config.dynamic_mode_enabled || false;
    settingsDynamicBaseJobs.value = config.dynamic_mode_base_jobs || 1;
    settingsDynamicMaxJobs.value = config.dynamic_mode_max_jobs || 10;
    settingsDynamicCpuThreshold.value = config.dynamic_mode_cpu_threshold || 75.0;
    settingsDynamicMemoryThreshold.value = config.dynamic_mode_memory_threshold || 80.0;
    settingsAutoBackupEnabled.checked = config.auto_backup_enabled || false;
    settingsAutoBackupInterval.value = config.auto_backup_interval || 3600;
    settingsAutoBackupMaxCount.value = config.auto_backup_max_count || 10;
    const templateValues = config.tool_flag_templates || {};
    Object.entries(templateInputs).forEach(([key, el]) => {
      if (!el) return;
      el.value = templateValues[key] || '';
    });
  }

  if (!launchFormDirty) {
    launchWordlist.value = config.default_wordlist || '';
    launchInterval.value = config.default_interval || 30;
    launchSkipNikto.checked = !!config.skip_nikto_by_default;
  }
}



// Store last ETag for caching
let lastStateETag = null;

