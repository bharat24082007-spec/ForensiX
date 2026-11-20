/**
 * ForensiX Vendored Lightweight vis-network Engine
 * Provides an interactive HTML5 Canvas force-directed graph renderer.
 * Zero external CDN links; 100% offline self-contained.
 */
(function (global) {
  'use strict';

  var vis = global.vis || {};

  function Network(container, data, options) {
    this.container = typeof container === 'string' ? document.getElementById(container) : container;
    this.nodes = (data && data.nodes) ? data.nodes.slice() : [];
    this.edges = (data && data.edges) ? data.edges.slice() : [];
    this.options = options || {};
    this.listeners = {};
    this.transform = { x: 0, y: 0, scale: 1 };
    this.dragNode = null;
    this.isPanning = false;
    this.panStart = { x: 0, y: 0 };
    this.init();
  }

  Network.prototype.init = function () {
    if (!this.container) return;
    this.container.innerHTML = '';
    this.container.style.position = 'relative';

    this.canvas = document.createElement('canvas');
    this.canvas.style.width = '100%';
    this.canvas.style.height = '100%';
    this.canvas.style.display = 'block';
    this.container.appendChild(this.canvas);
    this.ctx = this.canvas.getContext('2d');

    this.resize();
    window.addEventListener('resize', this.resize.bind(this));

    // Initialize node positions in a circle/scatter if not set
    var width = this.canvas.width;
    var height = this.canvas.height;
    var centerX = width / 2;
    var centerY = height / 2;
    var radius = Math.min(width, height) * 0.35;
    var count = this.nodes.length;

    this.nodeMap = {};
    for (var i = 0; i < count; i++) {
      var node = this.nodes[i];
      var angle = (i / Math.max(count, 1)) * 2 * Math.PI;
      node.x = node.x || (centerX + radius * Math.cos(angle) + (Math.random() - 0.5) * 40);
      node.y = node.y || (centerY + radius * Math.sin(angle) + (Math.random() - 0.5) * 40);
      node.radius = node.size || 18;
      this.nodeMap[node.id] = node;
    }

    this.attachEvents();
    this.animate();
  };

  Network.prototype.resize = function () {
    var rect = this.container.getBoundingClientRect();
    this.canvas.width = rect.width * (window.devicePixelRatio || 1);
    this.canvas.height = rect.height * (window.devicePixelRatio || 1);
    this.ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);
    this.draw();
  };

  Network.prototype.on = function (event, callback) {
    if (!this.listeners[event]) this.listeners[event] = [];
    this.listeners[event].push(callback);
  };

  Network.prototype.emit = function (event, data) {
    var list = this.listeners[event] || [];
    for (var i = 0; i < list.length; i++) {
      list[i](data);
    }
  };

  Network.prototype.attachEvents = function () {
    var self = this;

    this.canvas.addEventListener('mousedown', function (e) {
      var pos = self.getCanvasPos(e);
      var clicked = self.findNodeAt(pos.x, pos.y);
      if (clicked) {
        self.dragNode = clicked;
        self.emit('click', { nodes: [clicked.id], node: clicked });
      } else {
        self.isPanning = true;
        self.panStart = { x: e.clientX - self.transform.x, y: e.clientY - self.transform.y };
        self.emit('click', { nodes: [], node: null });
      }
    });

    window.addEventListener('mousemove', function (e) {
      if (self.dragNode) {
        var pos = self.getCanvasPos(e);
        self.dragNode.x = pos.x;
        self.dragNode.y = pos.y;
        self.draw();
      } else if (self.isPanning) {
        self.transform.x = e.clientX - self.panStart.x;
        self.transform.y = e.clientY - self.panStart.y;
        self.draw();
      }
    });

    window.addEventListener('mouseup', function () {
      self.dragNode = null;
      self.isPanning = false;
    });

    this.canvas.addEventListener('wheel', function (e) {
      e.preventDefault();
      var zoom = e.deltaY < 0 ? 1.1 : 0.9;
      self.transform.scale = Math.max(0.2, Math.min(3.0, self.transform.scale * zoom));
      self.draw();
    });
  };

  Network.prototype.getCanvasPos = function (e) {
    var rect = this.canvas.getBoundingClientRect();
    var clientX = (e.clientX - rect.left - this.transform.x) / this.transform.scale;
    var clientY = (e.clientY - rect.top - this.transform.y) / this.transform.scale;
    return { x: clientX, y: clientY };
  };

  Network.prototype.findNodeAt = function (x, y) {
    for (var i = this.nodes.length - 1; i >= 0; i--) {
      var n = this.nodes[i];
      var dx = n.x - x;
      var dy = n.y - y;
      if (dx * dx + dy * dy <= n.radius * n.radius) {
        return n;
      }
    }
    return null;
  };

  Network.prototype.draw = function () {
    if (!this.ctx) return;
    var ctx = this.ctx;
    var width = this.canvas.width / (window.devicePixelRatio || 1);
    var height = this.canvas.height / (window.devicePixelRatio || 1);

    ctx.save();
    ctx.clearRect(0, 0, width, height);

    ctx.translate(this.transform.x, this.transform.y);
    ctx.scale(this.transform.scale, this.transform.scale);

    // Draw edges
    for (var i = 0; i < this.edges.length; i++) {
      var e = this.edges[i];
      var u = this.nodeMap[e.from];
      var v = this.nodeMap[e.to];
      if (u && v) {
        ctx.beginPath();
        ctx.moveTo(u.x, u.y);
        ctx.lineTo(v.x, v.y);
        ctx.strokeStyle = e.color || '#94a3b8';
        ctx.lineWidth = e.width || 1.5;
        ctx.stroke();

        if (e.label) {
          var mx = (u.x + v.x) / 2;
          var my = (u.y + v.y) / 2;
          ctx.font = '10px sans-serif';
          ctx.fillStyle = '#64748b';
          ctx.fillText(e.label, mx + 4, my - 4);
        }
      }
    }

    // Draw nodes
    for (var j = 0; j < this.nodes.length; j++) {
      var n = this.nodes[j];
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius, 0, 2 * Math.PI);
      ctx.fillStyle = n.color || '#3b82f6';
      ctx.fill();
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 2.5;
      ctx.stroke();

      // Label
      ctx.font = '11px sans-serif';
      ctx.fillStyle = '#0f172a';
      ctx.textAlign = 'center';
      ctx.fillText(n.label || String(n.id), n.x, n.y + n.radius + 14);
    }

    ctx.restore();
  };

  Network.prototype.animate = function () {
    var self = this;
    var step = 0;
    function tick() {
      if (step < 40) {
        // Light force relaxation
        for (var i = 0; i < self.nodes.length; i++) {
          for (var j = i + 1; j < self.nodes.length; j++) {
            var n1 = self.nodes[i];
            var n2 = self.nodes[j];
            var dx = n2.x - n1.x;
            var dy = n2.y - n1.y;
            var dist = Math.sqrt(dx * dx + dy * dy) || 1;
            if (dist < 120) {
              var force = (120 - dist) / 120 * 2;
              n1.x -= (dx / dist) * force;
              n1.y -= (dy / dist) * force;
              n2.x += (dx / dist) * force;
              n2.y += (dy / dist) * force;
            }
          }
        }
        self.draw();
        step++;
        requestAnimationFrame(tick);
      }
    }
    requestAnimationFrame(tick);
  };

  vis.Network = Network;
  global.vis = vis;

})(typeof window !== 'undefined' ? window : this);
