async function fetchState() {
  try {
    // Build request with ETag support for caching
    const headers = {};
    if (lastStateETag) {
      headers['If-None-Match'] = lastStateETag;
    }
    
    const resp = await fetch('/api/state', { headers });
    
    // Check for 304 Not Modified - no need to update
    if (resp.status === 304) {
      // Data unchanged, just update timestamp
      const now = new Date().toISOString();
      document.getElementById('last-updated').textContent = 'Last updated: ' + now + ' (cached)';
      return;
    }
    
    if (!resp.ok) throw new Error('Failed to fetch state');
    
    // Store new ETag for next request
    const etag = resp.headers.get('ETag');
    if (etag) {
      lastStateETag = etag;
    }
    
    const data = await resp.json();
    latestConfig = data.config || {};
    latestRunningJobs = data.running_jobs || [];
    latestQueuedJobs = data.queued_jobs || [];
    latestTargetsData = data.targets || {};
    document.getElementById('last-updated').textContent = 'Last updated: ' + (data.last_updated || 'never');
    renderJobs(data.running_jobs || []);
    renderQueue(data.queued_jobs || []);
    renderOverviewTargets(data.targets || {});
    renderJsFindingsOverview(data.targets || {});
    renderTargets(data.targets || {});
    renderSettings(data.config || {}, data.tools || {});
    renderWorkers(data.workers || {});
    renderReports(data.targets || {});
    renderMonitors(data.monitors || []);
    renderGallery(data.targets || {});
    
    // Fetch and render system resources
    await fetchSystemResources();
    
    // Restore collapsible states after rendering
    restoreAllCollapsibleStates();
    
    // Update logs view if visible
    const logsSection = document.querySelector('[data-view="logs"]');
    if (logsSection && logsSection.classList.contains('active')) {
      await updateLogsView();
    }
  } catch (err) {
    targetsList.innerHTML = `<div class="section-placeholder">${escapeHtml(err.message)}</div>`;
  }
}

launchForm.addEventListener('input', () => { launchFormDirty = true; });

if (settingsForm) {
  settingsForm.addEventListener('input', () => { settingsFormDirty = true; });
} else {
  console.error('Settings form not found!');
}

if (settingsWordlistUpload) {
  settingsWordlistUpload.addEventListener('click', async () => {
    const file = settingsWordlistFile && settingsWordlistFile.files && settingsWordlistFile.files[0];
    if (!file) {
      if (settingsWordlistStatus) settingsWordlistStatus.textContent = 'Choose a .txt file first.';
      return;
    }
    if (settingsWordlistStatus) settingsWordlistStatus.textContent = 'Uploading...';
    try {
      const content = await file.text();
      const resp = await fetch('/api/wordlist/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: file.name, content }),
      });
      const data = await resp.json();
      if (data.success && data.path) {
        if (settingsWordlist) settingsWordlist.value = data.path;
        if (launchWordlist && !launchFormDirty) launchWordlist.value = data.path;
        settingsFormDirty = true;
        if (settingsWordlistStatus) settingsWordlistStatus.textContent = data.message || 'Uploaded.';
      } else {
        if (settingsWordlistStatus) settingsWordlistStatus.textContent = data.message || 'Upload failed.';
      }
    } catch (err) {
      if (settingsWordlistStatus) settingsWordlistStatus.textContent = 'Upload failed: ' + err;
    }
  });
}


targetsList.addEventListener('click', (event) => {
  const btn = event.target.closest('.sub-link');
  if (!btn) return;
  event.preventDefault();
  const domain = btn.getAttribute('data-domain');
  const sub = btn.getAttribute('data-sub');
  openSubdomainDetail(domain, sub);
});

detailClose.addEventListener('click', () => closeDetailModal());
detailOverlay.addEventListener('click', (event) => {
  if (event.target === detailOverlay) closeDetailModal();
});

launchForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = {
    domain: event.target.domain.value,
    wordlist: launchWordlist.value,
    interval: launchInterval.value,
    skip_nikto: launchSkipNikto.checked,
  };
  launchStatus.textContent = 'Dispatching...';
  launchStatus.className = 'status';
  try {
    const resp = await fetch('/api/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    launchStatus.textContent = data.message || 'Done';
    launchStatus.className = 'status ' + (data.success ? 'success' : 'error');
    if (data.success) {
      event.target.reset();
      launchFormDirty = false;
      fetchState();
    }
  } catch (err) {
    launchStatus.textContent = err.message;
    launchStatus.className = 'status error';
  }
});

if (importFile) {
  importFile.addEventListener('change', async () => {
    const file = importFile.files && importFile.files[0];
    if (!file) return;
    try {
      importContent.value = await file.text();
      importStatus.textContent = 'Loaded ' + file.name + ' (' + importContent.value.length + ' chars). Review and click Import & Run.';
      importStatus.className = 'status';
    } catch (err) {
      importStatus.textContent = 'Could not read file: ' + err.message;
      importStatus.className = 'status error';
    }
  });
}

if (importForm) {
  importForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const content = importContent.value.trim();
    if (!content) {
      importStatus.textContent = 'Provide a file or paste a domain list first.';
      importStatus.className = 'status error';
      return;
    }
    importStatus.textContent = 'Importing…';
    importStatus.className = 'status';
    try {
      const resp = await fetch('/api/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, skip_nikto: importSkipNikto.checked }),
      });
      const data = await resp.json();
      importStatus.textContent = data.message || 'Done';
      importStatus.className = 'status ' + (data.success ? 'success' : 'error');
      if (data.success) {
        importContent.value = '';
        if (importFile) importFile.value = '';
        fetchState();
      }
    } catch (err) {
      importStatus.textContent = err.message;
      importStatus.className = 'status error';
    }
  });
}

if (settingsForm) {
  // Create the save settings function that can be called from anywhere
  window.saveSettingsNow = async function() {
    try {
      console.log('[DEBUG] saveSettingsNow called');
      
      // Validate all required elements exist
      if (!settingsStatus) {
        console.error('settingsStatus element not found');
        alert('Error: Settings status element not found. Please refresh the page.');
        return;
      }
      
      settingsStatus.textContent = 'Saving...';
      settingsStatus.className = 'status';
      
      const payload = {
        default_wordlist: settingsWordlist ? settingsWordlist.value : '',
        default_interval: settingsInterval ? settingsInterval.value : '',
        wildcard_tlds: settingsWildcardTlds ? settingsWildcardTlds.value : '',
        skip_nikto_by_default: settingsSkipNikto ? settingsSkipNikto.checked : false,
        enable_screenshots: settingsEnableScreenshots ? settingsEnableScreenshots.checked : true,
        enable_amass: settingsEnableAmass ? settingsEnableAmass.checked : true,
        amass_timeout: settingsAmassTimeout ? settingsAmassTimeout.value : '',
        dns_resolvers: settingsDnsResolvers ? settingsDnsResolvers.value : '',

        enable_subfinder: settingsEnableSubfinder ? settingsEnableSubfinder.checked : true,
        enable_assetfinder: settingsEnableAssetfinder ? settingsEnableAssetfinder.checked : true,
        enable_findomain: settingsEnableFindomain ? settingsEnableFindomain.checked : true,
        enable_sublist3r: settingsEnableSublist3r ? settingsEnableSublist3r.checked : true,
        enable_crtsh: settingsEnableCrtsh ? settingsEnableCrtsh.checked : true,
        enable_github_subdomains: settingsEnableGithubSubdomains ? settingsEnableGithubSubdomains.checked : true,
        enable_dnsx: settingsEnableDnsx ? settingsEnableDnsx.checked : true,
        enable_waybackurls: settingsEnableWaybackurls ? settingsEnableWaybackurls.checked : true,
        enable_gau: settingsEnableGau ? settingsEnableGau.checked : true,
        enable_js_scan: settingsEnableJsScan ? settingsEnableJsScan.checked : true,
        use_bundled_nuclei_templates: settingsBundledNucleiTemplates ? settingsBundledNucleiTemplates.checked : true,
        subfinder_threads: settingsSubfinderThreads ? settingsSubfinderThreads.value : '',
        assetfinder_threads: settingsAssetfinderThreads ? settingsAssetfinderThreads.value : '',
        findomain_threads: settingsFindomainThreads ? settingsFindomainThreads.value : '',
        global_rate_limit: settingsGlobalRateLimit ? settingsGlobalRateLimit.value : '',
        max_running_jobs: settingsMaxJobs ? settingsMaxJobs.value : '',
        default_tool_workers: settingsDefaultToolWorkers ? settingsDefaultToolWorkers.value : '',
        max_parallel_amass: settingsAmass ? settingsAmass.value : '',
        max_parallel_subfinder: settingsSubfinder ? settingsSubfinder.value : '',
        max_parallel_assetfinder: settingsAssetfinder ? settingsAssetfinder.value : '',
        max_parallel_findomain: settingsFindomain ? settingsFindomain.value : '',
        max_parallel_sublist3r: settingsSublist3r ? settingsSublist3r.value : '',
        max_parallel_crtsh: settingsCrtsh ? settingsCrtsh.value : '',
        max_parallel_github_subdomains: settingsGithubSubdomains ? settingsGithubSubdomains.value : '',
        max_parallel_dnsx: settingsDnsx ? settingsDnsx.value : '',
        max_parallel_httpx: settingsHttpx ? settingsHttpx.value : '',
        max_parallel_ffuf: settingsFFUF ? settingsFFUF.value : '',
        max_parallel_waybackurls: settingsWaybackurls ? settingsWaybackurls.value : '',
        max_parallel_gau: settingsGau ? settingsGau.value : '',
        max_parallel_nuclei: settingsNuclei ? settingsNuclei.value : '',
        max_parallel_nikto: settingsNikto ? settingsNikto.value : '',
        max_parallel_gowitness: settingsGowitness ? settingsGowitness.value : '',
        dynamic_mode_enabled: settingsDynamicMode ? settingsDynamicMode.checked : false,
        dynamic_mode_base_jobs: settingsDynamicBaseJobs ? settingsDynamicBaseJobs.value : '',
        dynamic_mode_max_jobs: settingsDynamicMaxJobs ? settingsDynamicMaxJobs.value : '',
        dynamic_mode_cpu_threshold: settingsDynamicCpuThreshold ? settingsDynamicCpuThreshold.value : '',
        dynamic_mode_memory_threshold: settingsDynamicMemoryThreshold ? settingsDynamicMemoryThreshold.value : '',
        auto_backup_enabled: settingsAutoBackupEnabled ? settingsAutoBackupEnabled.checked : false,
        auto_backup_interval: settingsAutoBackupInterval ? settingsAutoBackupInterval.value : '',
        auto_backup_max_count: settingsAutoBackupMaxCount ? settingsAutoBackupMaxCount.value : '',
      };
      
      const templatePayload = {};
      Object.entries(templateInputs).forEach(([key, el]) => {
        if (!el) return;
        templatePayload[key] = el.value || '';
      });
      payload.tool_flag_templates = templatePayload;
      
      console.log('Sending settings payload:', payload);
      
      const resp = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      
      console.log('Response status:', resp.status);
      const data = await resp.json();
      console.log('Response data:', data);
      
      settingsStatus.textContent = data.message || 'Saved';
      settingsStatus.className = 'status ' + (data.success ? 'success' : 'error');
      if (data.success) {
        settingsFormDirty = false;
        fetchState();
      }
    } catch (err) {
      console.error('Settings form submission error:', err);
      if (settingsStatus) {
        settingsStatus.textContent = 'Error: ' + err.message;
        settingsStatus.className = 'status error';
      } else {
        alert('Error saving settings: ' + err.message);
      }
    }
  };
  
  // Attach to form submit event
  settingsForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    console.log('[DEBUG] Form submit event fired');
    await window.saveSettingsNow();
  }, true); // Use capture phase
  
  // Also add a direct button click handler with capture
  if (settingsSaveBtn) {
    settingsSaveBtn.addEventListener('click', async (event) => {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      console.log('[DEBUG] Save button clicked directly (addEventListener), calling saveSettingsNow');
      await window.saveSettingsNow();
    }, true); // Use capture phase to intercept before any other handler
  } else {
    console.error('[DEBUG] settingsSaveBtn not found!');
  }
  
  // Add Enter key support for all settings inputs with capture
  const settingsInputs = settingsForm.querySelectorAll('input, textarea, select');
  console.log('[DEBUG] Found', settingsInputs.length, 'form inputs for Enter key binding');
  settingsInputs.forEach(input => {
    input.addEventListener('keydown', async (event) => {
      if (event.key === 'Enter' && event.target.tagName !== 'TEXTAREA') {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();
        console.log('[DEBUG] Enter pressed in', event.target.id || event.target.name, ', calling saveSettingsNow');
        await window.saveSettingsNow();
      }
    }, true); // Use capture phase
  });
  
  console.log('[DEBUG] Settings form handlers attached. Form ID:', settingsForm.id, 'Button:', settingsSaveBtn ? 'found' : 'NOT FOUND');
} else {
  console.error('Cannot attach submit handler: settingsForm is null');
}

// API Keys functionality
const apiKeysForm = document.getElementById('api-keys-form');
const apiKeysStatus = document.getElementById('api-keys-status');

// Load existing API keys when settings tab is viewed
async function loadApiKeys() {
  try {
    const resp = await fetch('/api/api-keys');
    if (!resp.ok) throw new Error('Failed to load API keys');
    const data = await resp.json();
    
    // Populate Amass keys
    const amassKeys = data.amass || {};
    AMASS_PROVIDERS.forEach(provider => {
      const input = document.getElementById(`amass-${provider}`);
      if (input && amassKeys[provider]) {
        input.value = amassKeys[provider];
      }
    });
    
    // Populate Subfinder keys
    const subfinderKeys = data.subfinder || {};
    const githubInput = document.getElementById('subfinder-github');
    if (githubInput && subfinderKeys.github) {
      githubInput.value = subfinderKeys.github;
    }
  } catch (err) {
    console.error('Error loading API keys:', err);
  }
}

// Save API keys form handler
if (apiKeysForm) {
  apiKeysForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    
    const amassKeys = {};
    AMASS_PROVIDERS.forEach(provider => {
      const input = document.getElementById(`amass-${provider}`);
      if (input && input.value.trim()) {
        amassKeys[provider] = input.value.trim();
      }
    });
    
    const subfinderKeys = {};
    const githubInput = document.getElementById('subfinder-github');
    if (githubInput && githubInput.value.trim()) {
      subfinderKeys.github = githubInput.value.trim();
    }
    
    // Copy shared keys to Subfinder
    SUBFINDER_SHARED_PROVIDERS.forEach(provider => {
      if (amassKeys[provider]) {
        subfinderKeys[provider] = amassKeys[provider];
      }
    });
    
    try {
      const resp = await fetch('/api/api-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amass: amassKeys, subfinder: subfinderKeys })
      });
      
      if (!resp.ok) throw new Error('Failed to save API keys');
      const result = await resp.json();
      
      if (result.success) {
        apiKeysStatus.textContent = result.message || 'API keys saved successfully';
        apiKeysStatus.className = 'status success';
        setTimeout(() => {
          apiKeysStatus.textContent = '';
          apiKeysStatus.className = 'status';
        }, 3000);
      } else {
        apiKeysStatus.textContent = result.message || 'Failed to save API keys';
        apiKeysStatus.className = 'status error';
      }
    } catch (err) {
      apiKeysStatus.textContent = err.message;
      apiKeysStatus.className = 'status error';
    }
  });
}

// Load API keys when switching to API Keys tab
settingsTabs.forEach(tab => {
  tab.addEventListener('click', () => {
    if (tab.dataset.tab === 'api-keys') {
      loadApiKeys();
    }
  });
});

// Backup functionality
async function loadBackups() {
  try {
    const resp = await fetch('/api/backups');
    if (!resp.ok) throw new Error('Failed to load backups');
    const data = await resp.json();
    renderBackupsList(data.backups || []);
  } catch (err) {
    if (backupList) {
      backupList.innerHTML = `<p class="muted">Error loading backups: ${escapeHtml(err.message)}</p>`;
    }
  }
}

function renderBackupsList(backups) {
  if (!backupList) return;
  
  if (backups.length === 0) {
    backupList.innerHTML = '<p class="muted">No backups available</p>';
    return;
  }
  
  const html = backups.map(backup => {
    const date = new Date(backup.created);
    const dateStr = date.toLocaleString();
    return `
      <div class="backup-item" style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #0f172a; border-radius: 6px; margin-bottom: 8px;">
        <div>
          <strong>${escapeHtml(backup.filename)}</strong>
          <div class="muted" style="font-size: 0.85rem;">${dateStr} · ${backup.size_mb} MB</div>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn" onclick="downloadBackup('${escapeHtml(backup.filename)}')">Download</button>
          <button class="btn" onclick="restoreBackup('${escapeHtml(backup.filename)}')">Restore</button>
          <button class="btn" onclick="deleteBackup('${escapeHtml(backup.filename)}')" style="background: #dc2626;">Delete</button>
        </div>
      </div>
    `;
  }).join('');
  
  backupList.innerHTML = html;
}

