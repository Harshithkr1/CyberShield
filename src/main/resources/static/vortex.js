/*
 * Cyber Shield - vortex background (dependency-free, Canvas 2D)
 *
 * Idea: a "threat funnel". Scam messages swirl in from the top and are
 * squeezed through a narrow neck (the analyzer) onto a calm floor.
 * The funnel changes colour/speed with the risk level of the last result.
 *
 * Usage:
 *   <canvas id="vortex"></canvas>
 *   <script src="js/vortex.js"></script>
 *   window.cyberVortex.setMood('scanning');   // while the API call is running
 *   window.cyberVortex.setMood('critical');   // after a result: calm|low|medium|high|critical
 *   window.cyberVortex.pulse();               // short energy burst
 */
(function () {
  'use strict';

  var TAU = Math.PI * 2;

  var MOODS = {
    calm:     { r: 232, g: 236, b: 244, speed: 1.0, energy: 1.0 },
    scanning: { r: 110, g: 225, b: 255, speed: 2.6, energy: 1.35 },
    low:      { r: 96,  g: 232, b: 160, speed: 1.0, energy: 1.1 },
    medium:   { r: 255, g: 205, b: 90,  speed: 1.3, energy: 1.2 },
    high:     { r: 255, g: 150, b: 70,  speed: 1.8, energy: 1.4 },
    critical: { r: 255, g: 80,  b: 80,  speed: 2.4, energy: 1.7 }
  };

  function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
  function lerp(a, b, k) { return a + (b - a) * k; }

  function create(canvas) {
    var ctx = canvas.getContext('2d');
    var reduceMotion = window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    var W = 0, H = 0, dpr = 1, mobile = false;
    var STRANDS = 150, RINGS = 44, FLOOR = 64, PARTICLES = 140;
    var t = 2, last = 0, raf = 0, running = false, visible = true;
    var boost = 0, scrollK = 0;
    var cur = Object.assign({}, MOODS.calm);
    var tgt = Object.assign({}, MOODS.calm);
    var pointer = { x: 0, y: 0, tx: 0, ty: 0 };
    var parts = [];

    function seedParticles() {
      parts = [];
      for (var i = 0; i < PARTICLES; i++) {
        parts.push({
          phi: Math.random() * TAU,
          u: Math.random() * 1.1,
          v: 0.05 + Math.random() * 0.09,
          s: Math.random() < 0.15 ? 1.8 : 1.0,
          a: 0.25 + Math.random() * 0.6
        });
      }
    }

    function resize() {
      var r = canvas.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      W = Math.max(1, r.width);
      H = Math.max(1, r.height);
      canvas.width = Math.round(W * dpr);
      canvas.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      mobile = W < 700;
      STRANDS = mobile ? 70 : 150;
      RINGS = mobile ? 24 : 44;
      FLOOR = mobile ? 36 : 64;
      PARTICLES = mobile ? 60 : 140;
      seedParticles();
      draw();
    }

    /* point on the funnel: u = 0 at the neck, u = 1 at the top edge of the hero */
    function radius(u, rn, Rtop) {
      var a = Math.abs(u);
      return rn + (Rtop - rn) * Math.pow(a, 2.3) * (u < 0 ? 0.5 : 1);
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);

      var e = clamp(cur.energy + boost * 0.8, 0.5, 2.2);
      var col = Math.round(cur.r) + ',' + Math.round(cur.g) + ',' + Math.round(cur.b);
      var cx = W / 2 + pointer.x * W * 0.025;
      var yn = H * 0.71 - scrollK * H * 0.08;               /* neck height */
      var rn = Math.max(16, W * 0.05) * (1 + boost * 0.7);  /* neck radius */
      var Rtop = W * 0.32;
      var tilt = 0.16 + pointer.y * 0.035;
      var rot = t;
      var uMin = -0.04, uMax = 1.14;
      var S = mobile ? 28 : 40;

      /* ---- twisted strands (two directions give the woven mesh) ---- */
      var front = new Path2D(), back = new Path2D();
      for (var i = 0; i < STRANDS; i++) {
        var phi = i * 0.6180339887 * TAU;
        var dir = (i & 1) ? 1 : -1;
        var tw = 2.7 + 0.5 * Math.sin(i * 1.7);
        var px = 0, py = 0;
        for (var j = 0; j <= S; j++) {
          var u = uMin + (uMax - uMin) * (j / S);
          var R = radius(u, rn, Rtop);
          var th = phi + dir * tw * u + rot * 0.6;
          var X = R * Math.cos(th), Z = R * Math.sin(th);
          var sx = cx + X, sy = yn - u * yn + Z * tilt;
          if (j > 0) {
            var p = (Z > 0) ? front : back;
            p.moveTo(px, py); p.lineTo(sx, sy);
          }
          px = sx; py = sy;
        }
      }
      ctx.lineWidth = 0.7;
      ctx.strokeStyle = 'rgba(' + col + ',' + (0.14 * e).toFixed(3) + ')';
      ctx.stroke(back);
      ctx.strokeStyle = 'rgba(' + col + ',' + (0.46 * e).toFixed(3) + ')';
      ctx.stroke(front);

      /* ---- horizontal rings on the funnel ---- */
      var rf = new Path2D(), rb = new Path2D();
      for (var k = 0; k < RINGS; k++) {
        var uk = uMin + (uMax - uMin) * Math.pow((k + 0.5) / RINGS, 1.25);
        var Rk = radius(uk, rn, Rtop);
        var yk = yn - uk * yn;
        var N = 72, qx = 0, qy = 0;
        for (var n = 0; n <= N; n++) {
          var a = (n / N) * TAU;
          var rr = Rk * (1 + 0.012 * Math.sin(3 * a + rot * 2 + k));
          var x2 = cx + rr * Math.cos(a), y2 = yk + rr * Math.sin(a) * tilt;
          if (n > 0) {
            var pp = Math.sin(a) > 0 ? rf : rb;
            pp.moveTo(qx, qy); pp.lineTo(x2, y2);
          }
          qx = x2; qy = y2;
        }
      }
      ctx.lineWidth = 0.6;
      ctx.strokeStyle = 'rgba(' + col + ',' + (0.06 * e).toFixed(3) + ')';
      ctx.stroke(rb);
      ctx.strokeStyle = 'rgba(' + col + ',' + (0.2 * e).toFixed(3) + ')';
      ctx.stroke(rf);

      /* ---- floor: concentric ripples spreading from the neck ---- */
      var yf = yn + H * 0.03;
      for (var f = 0; f < FLOOR; f++) {
        var q = f / FLOOR;
        var rad = rn * 1.3 + W * 0.95 * Math.pow(q, 1.4);
        var squash = 0.2 + pointer.y * 0.02;
        var alpha = (0.62 - 0.45 * q) * 0.95 * e;
        ctx.beginPath();
        var M = 110;
        for (var m = 0; m <= M; m++) {
          var b = (m / M) * TAU;
          var r2 = rad * (1 + 0.016 * Math.sin(6 * b - rot * 1.6 + f * 0.4));
          var fx = cx + r2 * Math.cos(b), fy = yf + r2 * Math.sin(b) * squash;
          if (m === 0) ctx.moveTo(fx, fy); else ctx.lineTo(fx, fy);
        }
        ctx.lineWidth = 0.6;
        ctx.strokeStyle = 'rgba(' + col + ',' + clamp(alpha, 0.02, 0.6).toFixed(3) + ')';
        ctx.stroke();
      }

      /* ---- particles falling toward the neck ---- */
      ctx.fillStyle = 'rgba(' + col + ',0.9)';
      for (var pI = 0; pI < parts.length; pI++) {
        var P = parts[pI];
        var Rp = radius(P.u, rn, Rtop);
        var thp = P.phi + 2.7 * P.u + rot * 0.6;
        var Zp = Rp * Math.sin(thp);
        var xp = cx + Rp * Math.cos(thp), yp = yn - P.u * yn + Zp * tilt;
        ctx.globalAlpha = P.a * (Zp > 0 ? 1 : 0.35) * clamp(e, 0.6, 1.5);
        ctx.fillRect(xp, yp, P.s, P.s);
      }
      ctx.globalAlpha = 1;
    }

    function step(dt) {
      var k = 1 - Math.exp(-dt * 3);
      cur.r = lerp(cur.r, tgt.r, k);
      cur.g = lerp(cur.g, tgt.g, k);
      cur.b = lerp(cur.b, tgt.b, k);
      cur.speed = lerp(cur.speed, tgt.speed, k);
      cur.energy = lerp(cur.energy, tgt.energy, k);
      boost *= Math.exp(-dt * 2.2);
      pointer.x = lerp(pointer.x, pointer.tx, 1 - Math.exp(-dt * 4));
      pointer.y = lerp(pointer.y, pointer.ty, 1 - Math.exp(-dt * 4));
      t += dt * 0.35 * (cur.speed + boost * 2);
      for (var i = 0; i < parts.length; i++) {
        var P = parts[i];
        P.u -= dt * P.v * (cur.speed + boost * 2);
        if (P.u < -0.02) { P.u = 1.1; P.phi = Math.random() * TAU; }
      }
    }

    function frame(ts) {
      if (!running) return;
      var dt = Math.min(0.05, (ts - last) / 1000 || 0.016);
      last = ts;
      step(dt);
      draw();
      raf = requestAnimationFrame(frame);
    }

    function start() {
      if (reduceMotion || running || !visible || document.hidden) return;
      running = true; last = performance.now();
      raf = requestAnimationFrame(frame);
    }
    function stop() { running = false; cancelAnimationFrame(raf); }

    function onPointer(ev) {
      var r = canvas.getBoundingClientRect();
      pointer.tx = clamp((ev.clientX - r.left) / r.width - 0.5, -0.5, 0.5) * 2;
      pointer.ty = clamp((ev.clientY - r.top) / r.height - 0.5, -0.5, 0.5) * 2;
    }
    function onScroll() {
      var r = canvas.parentElement.getBoundingClientRect();
      scrollK = clamp(-r.top / Math.max(1, r.height), 0, 1);
      canvas.style.opacity = String(1 - scrollK * 0.85);
      if (reduceMotion) draw();
    }

    window.addEventListener('resize', resize);
    window.addEventListener('pointermove', onPointer, { passive: true });
    window.addEventListener('scroll', onScroll, { passive: true });
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) stop(); else start();
    });
    if ('IntersectionObserver' in window) {
      new IntersectionObserver(function (en) {
        visible = en[0].isIntersecting;
        if (visible) start(); else stop();
      }).observe(canvas);
    }

    resize();
    start();

    return {
      setMood: function (name) {
        var m = MOODS[name] || MOODS.calm;
        tgt = Object.assign({}, m);
        if (reduceMotion) { cur = Object.assign({}, m); draw(); }
      },
      pulse: function () { boost = 1; if (reduceMotion) draw(); },
      destroy: function () { stop(); window.removeEventListener('resize', resize); }
    };
  }

  function boot() {
    var c = document.getElementById('vortex');
    if (c && !window.cyberVortex) window.cyberVortex = create(c);
  }
  window.CyberVortex = { create: create };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();

