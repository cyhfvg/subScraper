let jobsViewFilter = "all";
let jobsSearchQuery = "";

function jobTone(status) {
  const value = (status || "").toLowerCase();
  if (value === "paused" || value === "pausing") return "paused";
  if (value === "completed" || value === "completed_with_errors") return "completed";
  if (value === "failed" || value === "error" || value === "cancelled") return "failed";
  return "running";
}

function classifyJobs(jobs) {
  const all = Array.isArray(jobs) ? jobs : [];
  const running = all.filter((job) => job.status !== "queued");
  return {
    all: running,
    active: running.filter((job) => !job.completed_at && job.status !== "paused" && job.status !== "pausing"),
    paused: running.filter((job) => job.status === "paused" || job.status === "pausing"),
    completed: running.filter((job) => job.completed_at),
  };
}

function renderJobControls(job) {
  if (!job || !job.domain) return "";
  const deleteAttr = job.job_id
    ? `data-delete-job-id="${escapeHtml(job.job_id)}"`
    : `data-delete-job="${escapeHtml(job.domain)}"`;
  const deleteBtn = `<button class="btn danger small" ${deleteAttr} data-delete-domain="${escapeHtml(job.domain || "")}">Delete</button>`;
  if (job.status === "running" || job.status === "dispatching" || job.status === "cancelling") {
    return `<div class="job-actions"><button class="btn secondary small" data-pause-job="${escapeHtml(job.domain)}">Pause</button>${deleteBtn}</div>`;
  }
  if (job.status === "paused" || job.status === "pausing") {
    return `<div class="job-actions"><button class="btn small" data-resume-job="${escapeHtml(job.domain)}">Resume</button>${deleteBtn}</div>`;
  }
  return `<div class="job-actions">${deleteBtn}</div>`;
}

function renderJobs(jobs) {
  const groups = classifyJobs(jobs);
  const countAll = document.getElementById("jobs-count-all");
  const countActive = document.getElementById("jobs-count-active");
  const countPaused = document.getElementById("jobs-count-paused");
  const countCompleted = document.getElementById("jobs-count-completed");
  if (countAll) countAll.textContent = String(groups.all.length);
  if (countActive) countActive.textContent = String(groups.active.length);
  if (countPaused) countPaused.textContent = String(groups.paused.length);
  if (countCompleted) countCompleted.textContent = String(groups.completed.length);
  if (typeof statActive !== "undefined" && statActive) {
    statActive.textContent = `${groups.active.length}${groups.completed.length ? ` (+ ${groups.completed.length} completed)` : ""}`;
  }

  let visible = groups[jobsViewFilter] || groups.all;
  const query = (jobsSearchQuery || "").trim().toLowerCase();
  if (query) {
    visible = visible.filter((job) => String(job.domain || "").toLowerCase().includes(query));
  }
  const sortedJobs = visible;

  if (!sortedJobs.length) {
    jobsList.innerHTML = `
      <div class="jobs-empty">
        <h3>No matching jobs</h3>
        <p class="muted">Launch a scan or clear the filter to see pipeline cards here.</p>
      </div>`;
    const pagerEl = document.getElementById("jobs-pagination");
    if (pagerEl) pagerEl.innerHTML = "";
    return;
  }

  jobsPaginationState.totalPages = Math.max(1, Math.ceil(sortedJobs.length / jobsPaginationState.pageSize));
  if (jobsPaginationState.currentPage > jobsPaginationState.totalPages) {
    jobsPaginationState.currentPage = jobsPaginationState.totalPages;
  }
  const startIdx = (jobsPaginationState.currentPage - 1) * jobsPaginationState.pageSize;
  const pageJobs = sortedJobs.slice(startIdx, startIdx + jobsPaginationState.pageSize);

  const cards = pageJobs.map((job) => {
    const progress = Math.max(0, Math.min(100, job.progress || 0));
    const steps = job.steps || {};
    const stepsHtml = Object.keys(steps).map((step) => renderJobStep(step, steps[step], job.domain)).join("");
    const logsHtml = renderLogEntries(job.logs || []);
    const tone = jobTone(job.status);
    return `
      <div class="job-card is-${tone}">
        <div class="job-card-accent"></div>
        <div class="job-card-body">
          <div class="job-summary">
            <div>
              <div class="job-title">${escapeHtml(job.domain || "")}</div>
              <div class="muted">Started ${fmtTime(job.started)}</div>
              ${job.completed_at ? `<div class="muted">Completed ${fmtTime(job.completed_at)}</div>` : ""}
            </div>
            <div class="job-summary-meta">
              <span class="status-pill ${statusClass(job.status)}">${statusLabel(job.status)}</span>
              <span class="badge">${progress}%</span>
            </div>
          </div>
          ${renderProgress(progress, job.status)}
          <div class="job-meta-chips">
            <span>Wordlist ${escapeHtml(job.wordlist || "default")}</span>
            <span>Interval ${escapeHtml(job.interval || 0)}s</span>
            <span>Nikto ${job.skip_nikto ? "skipped" : "on"}</span>
          </div>
          <div class="job-message">${escapeHtml(job.message || "")}</div>
          ${renderJobControls(job)}
          <button type="button" class="job-steps-toggle" data-toggle-job-details>Toggle steps &amp; logs</button>
          <div class="job-steps">${stepsHtml || '<p class="muted">Awaiting step updates…</p>'}</div>
          <div class="job-log">${logsHtml}</div>
        </div>
      </div>`;
  });
  jobsList.innerHTML = cards.join("");
  renderJobsPagination(sortedJobs.length);
}

async function handleJobDelete(domain, jobId, button) {
  if (!confirm(`Delete job ${domain || jobId}? Running scans stop at the next checkpoint.`)) {
    return;
  }
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Deleting…";
  try {
    const resp = await fetch("/api/jobs/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: domain || "", job_id: jobId || "" }),
    });
    const data = await resp.json();
    button.textContent = data.message || original;
    if (data.success && typeof fetchState === "function") {
      fetchState();
    }
  } catch (err) {
    button.textContent = err.message || "Failed";
  } finally {
    setTimeout(() => {
      button.textContent = original;
      button.disabled = false;
    }, 2000);
  }
}

document.addEventListener("click", (event) => {
  const chip = event.target.closest("[data-jobs-filter]");
  if (chip) {
    jobsViewFilter = chip.getAttribute("data-jobs-filter") || "all";
    document.querySelectorAll("[data-jobs-filter]").forEach((el) => {
      el.classList.toggle("active", el === chip);
    });
    jobsPaginationState.currentPage = 1;
    renderJobs(typeof latestRunningJobs !== "undefined" ? latestRunningJobs : []);
    return;
  }
  const toggle = event.target.closest("[data-toggle-job-details]");
  if (toggle) {
    const card = toggle.closest(".job-card");
    if (card) card.classList.toggle("collapsed");
    return;
  }
  const deleteBtn = event.target.closest("[data-delete-job], [data-delete-job-id]");
  if (deleteBtn) {
    handleJobDelete(
      deleteBtn.getAttribute("data-delete-domain") || deleteBtn.getAttribute("data-delete-job") || "",
      deleteBtn.getAttribute("data-delete-job-id") || "",
      deleteBtn
    );
  }
});

const jobsSearch = document.getElementById("jobs-search");
if (jobsSearch) {
  jobsSearch.addEventListener("input", () => {
    jobsSearchQuery = jobsSearch.value || "";
    jobsPaginationState.currentPage = 1;
    renderJobs(typeof latestRunningJobs !== "undefined" ? latestRunningJobs : []);
  });
}
