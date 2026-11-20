/**
 * ForensiX Vendored Lightweight vis-timeline Engine
 * Completely offline, zero external CDN dependencies.
 * Provides vis.DataSet and vis.Timeline minimal implementation
 * for interactive timeline visualization in browser.
 */
(function (global) {
  'use strict';

  var vis = global.vis || {};

  function DataSet(data) {
    this._data = Array.isArray(data) ? data.slice() : [];
  }

  DataSet.prototype.get = function () {
    return this._data;
  };

  DataSet.prototype.add = function (item) {
    this._data.push(item);
  };

  function Timeline(container, dataset, options) {
    this.container = typeof container === 'string' ? document.getElementById(container) : container;
    this.dataset = dataset;
    this.options = options || {};
    this.render();
  }

  Timeline.prototype.render = function () {
    if (!this.container) return;
    var items = this.dataset.get ? this.dataset.get() : [];
    this.container.innerHTML = '';

    if (!items || items.length === 0) {
      this.container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-muted);font-size:13px;">No timeline events to display.</div>';
      return;
    }

    var timelineWrapper = document.createElement('div');
    timelineWrapper.className = 'vis-timeline-custom';
    timelineWrapper.style.cssText = 'height:100%;display:flex;flex-direction:column;justify-content:space-between;padding:12px;overflow-x:auto;position:relative;background:var(--bg-surface);';

    var track = document.createElement('div');
    track.style.cssText = 'display:flex;gap:12px;align-items:center;height:80%;overflow-x:auto;padding-bottom:10px;';

    // Parse dates to sort chronologically
    var sorted = items.slice().sort(function (a, b) {
      return (a.start || '').localeCompare(b.start || '');
    });

    sorted.forEach(function (it) {
      var itemBox = document.createElement('div');
      itemBox.className = 'vis-item ' + (it.className || 'sev-info');
      itemBox.style.cssText = 'flex-shrink:0;min-width:180px;max-width:240px;border-radius:6px;padding:8px 10px;border-left:4px solid;font-size:12px;box-shadow:0 1px 3px rgba(0,0,0,0.08);background:var(--bg-surface-subtle);cursor:pointer;';
      
      var sev = (it.className || '').replace('sev-', '');
      var borderColors = {
        critical: '#ef4444',
        high: '#f59e0b',
        medium: '#38bdf8',
        low: '#22c55e',
        info: '#94a3b8'
      };
      itemBox.style.borderLeftColor = borderColors[sev] || '#94a3b8';

      var timeEl = document.createElement('div');
      timeEl.style.cssText = 'font-size:11px;color:var(--text-muted);margin-bottom:4px;font-family:monospace;';
      timeEl.textContent = it.start || '';

      var contentEl = document.createElement('div');
      contentEl.style.cssText = 'font-weight:600;color:var(--text-main);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;';
      contentEl.textContent = it.content || '';

      itemBox.appendChild(timeEl);
      itemBox.appendChild(contentEl);
      if (it.title) {
        itemBox.title = it.title.replace(/<[^>]+>/g, ' ');
      }
      track.appendChild(itemBox);
    });

    var axis = document.createElement('div');
    axis.style.cssText = 'border-top:2px solid var(--border-subtle);padding-top:6px;display:flex;justify-content:space-between;font-size:11px;color:var(--text-muted);';
    axis.innerHTML = '<span>' + (sorted[0].start || 'Start') + '</span><span>Chrono Timeline (UTC)</span><span>' + (sorted[sorted.length - 1].start || 'End') + '</span>';

    timelineWrapper.appendChild(track);
    timelineWrapper.appendChild(axis);
    this.container.appendChild(timelineWrapper);
  };

  vis.DataSet = DataSet;
  vis.Timeline = Timeline;
  global.vis = vis;

})(typeof window !== 'undefined' ? window : this);
