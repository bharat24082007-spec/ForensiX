/**
 * ForensiX Client-Side Architecture
 * Vanilla JavaScript (Zero external CDN / Framework dependencies)
 */

(function () {
  "use strict";

  // 1. Theme Management (Light / Dark Mode)
  function updateThemeIcon(theme) {
    const toggleBtn = document.getElementById("theme-toggle-btn");
    if (!toggleBtn) return;
    const useEl = toggleBtn.querySelector("use");
    if (useEl) {
      useEl.setAttribute("href", theme === "dark" ? "#icon-sun" : "#icon-moon");
    }
  }

  function initTheme() {
    const savedTheme = localStorage.getItem("forensix-theme") || "dark";
    document.documentElement.setAttribute("data-theme", savedTheme);
    updateThemeIcon(savedTheme);

    const toggleBtn = document.getElementById("theme-toggle-btn");
    if (toggleBtn) {
      toggleBtn.addEventListener("click", () => {
        const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
        const newTheme = currentTheme === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", newTheme);
        localStorage.setItem("forensix-theme", newTheme);
        updateThemeIcon(newTheme);
      });
    }
  }

  // 2. Monospace Hash Copying
  function initHashCopy() {
    document.addEventListener("click", (e) => {
      const copyBtn = e.target.closest(".copy-hash-btn");
      if (!copyBtn) return;

      const hashValue = copyBtn.getAttribute("data-hash");
      if (!hashValue) return;

      navigator.clipboard.writeText(hashValue).then(() => {
        const originalTitle = copyBtn.getAttribute("title");
        copyBtn.setAttribute("title", "Copied!");
        copyBtn.classList.add("text-success");

        setTimeout(() => {
          copyBtn.setAttribute("title", originalTitle || "Copy full hash");
          copyBtn.classList.remove("text-success");
        }, 1500);
      });
    });
  }

  // 3. Tab Switching
  function initTabs() {
    document.addEventListener("click", (e) => {
      const tab = e.target.closest(".tab-item[data-tab-target]");
      if (!tab) return;

      const container = tab.closest(".tabs-wrapper");
      if (!container) return;

      const targetId = tab.getAttribute("data-tab-target");
      const tabs = container.querySelectorAll(".tab-item");
      const panes = container.querySelectorAll(".tab-pane");

      tabs.forEach((t) => t.classList.remove("active"));
      panes.forEach((p) => p.classList.remove("active"));

      tab.classList.add("active");
      const targetPane = container.querySelector(targetId);
      if (targetPane) {
        targetPane.classList.add("active");
      }
    });
  }

  // 4. Modal Dialogs
  function initModals() {
    document.addEventListener("click", (e) => {
      const openTrigger = e.target.closest("[data-modal-open]");
      if (openTrigger) {
        const modalId = openTrigger.getAttribute("data-modal-open");
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.add("active");
      }

      const closeTrigger = e.target.closest("[data-modal-close]");
      if (closeTrigger) {
        const modal = closeTrigger.closest(".modal-overlay");
        if (modal) modal.classList.remove("active");
      }
    });
  }

  // 5. Asynchronous Job Status Poller
  function initJobPolling() {
    const activeBadges = document.querySelectorAll("[data-job-id][data-job-status='running'], [data-job-id][data-job-status='queued']");
    if (!activeBadges.length) return;

    activeBadges.forEach((badge) => {
      const jobId = badge.getAttribute("data-job-id");
      if (!jobId) return;

      const pollInterval = setInterval(() => {
        fetch(`/system/jobs/${jobId}/status`, { credentials: "same-origin" })
          .then((res) => {
            if (!res.ok) throw new Error("Status check failed");
            return res.json();
          })
          .then((data) => {
            if (!data || !data.status) return;
            const currentStatus = data.status.toLowerCase();
            badge.setAttribute("data-job-status", currentStatus);

            const textSpan = badge.querySelector(".job-status-text");
            if (textSpan) textSpan.textContent = currentStatus.toUpperCase();

            badge.classList.remove("chip-progress", "chip-unknown", "chip-verified", "chip-compromised");
            if (currentStatus === "done") {
              badge.classList.add("chip-verified");
              clearInterval(pollInterval);
            } else if (currentStatus === "failed") {
              badge.classList.add("chip-compromised");
              clearInterval(pollInterval);
            } else if (currentStatus === "running") {
              badge.classList.add("chip-progress");
            } else {
              badge.classList.add("chip-unknown");
            }
          })
          .catch(() => clearInterval(pollInterval));
      }, 2000);
    });
  }

  // DOM Ready Hook
  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initHashCopy();
    initTabs();
    initModals();
    initJobPolling();
  });
})();
