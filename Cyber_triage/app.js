/* ============================
   CYBER TRIAGE — APP LOGIC
   ============================ */

// ─── Navigation ───────────────────────────────────────────────────────────────

const sectionNames = {
  dashboard: 'Dashboard',
  import: 'Evidence Import',
  artifacts: 'Artifact Explorer',
  analysis: 'IOC Analysis',
  aiml: 'AI / ML Engine',
  timeline: 'Event Timeline',
  reports: 'Reports'
};

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    const target = item.dataset.section;

    // Update nav active state
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');

    // Update sections
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.getElementById('section-' + target).classList.add('active');

    // Update breadcrumb
    document.getElementById('breadcrumb-current').textContent = sectionNames[target];

    // Close sidebar on mobile
    if (window.innerWidth <= 768) {
      document.getElementById('sidebar').classList.remove('open');
    }
  });
});

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

// ─── Animated Counters ───────────────────────────────────────────────────────

function animateCounter(el, target, duration = 1600) {
  let start = 0;
  const step = target / (duration / 16);
  const timer = setInterval(() => {
    start += step;
    if (start >= target) { el.textContent = target; clearInterval(timer); }
    else { el.textContent = Math.floor(start); }
  }, 16);
}

window.addEventListener('DOMContentLoaded', () => {
  animateCounter(document.getElementById('risk-counter'), 82);
  animateCounter(document.getElementById('artifact-counter'), 3847);
  animateCounter(document.getElementById('ioc-counter'), 23);
  animateCounter(document.getElementById('files-counter'), 12491);

  drawThreatMap();
  drawGauge();
  startActivityFeed();
});

// ─── Threat Map Canvas ────────────────────────────────────────────────────────

function drawThreatMap() {
  const canvas = document.getElementById('threatCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 500;
  const H = canvas.offsetHeight || 220;
  canvas.width = W;
  canvas.height = H;

  const nodes = [];
  const nodeCount = 18;

  for (let i = 0; i < nodeCount; i++) {
    nodes.push({
      x: Math.random() * W,
      y: Math.random() * H,
      r: Math.random() * 3 + 2,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      color: Math.random() > 0.75 ? '#ff3a3a' : Math.random() > 0.5 ? '#ffb800' : '#00ffe5',
      pulse: Math.random() * Math.PI * 2
    });
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Draw connections
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          const alpha = (1 - dist / 120) * 0.4;
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.strokeStyle = `rgba(0, 255, 229, ${alpha})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }

    // Draw nodes
    nodes.forEach(n => {
      n.pulse += 0.03;
      const pulseR = n.r + Math.sin(n.pulse) * 1;

      // Glow
      const grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, pulseR * 4);
      grd.addColorStop(0, n.color + 'aa');
      grd.addColorStop(1, n.color + '00');
      ctx.beginPath();
      ctx.arc(n.x, n.y, pulseR * 4, 0, Math.PI * 2);
      ctx.fillStyle = grd;
      ctx.fill();

      // Core
      ctx.beginPath();
      ctx.arc(n.x, n.y, pulseR, 0, Math.PI * 2);
      ctx.fillStyle = n.color;
      ctx.fill();

      // Move
      n.x += n.vx;
      n.y += n.vy;
      if (n.x < 0 || n.x > W) n.vx *= -1;
      if (n.y < 0 || n.y > H) n.vy *= -1;
    });

    requestAnimationFrame(draw);
  }

  draw();
}

// ─── Gauge Canvas ─────────────────────────────────────────────────────────────

function drawGauge() {
  const canvas = document.getElementById('gaugeCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = 220, H = 130;
  canvas.width = W;
  canvas.height = H;

  const cx = W / 2, cy = H - 10;
  const r = 100;
  const value = 82;
  const startAngle = Math.PI;
  const endAngle = 0;
  const valueAngle = startAngle + (value / 100) * Math.PI;

  // Track
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, endAngle);
  ctx.strokeStyle = 'rgba(255,255,255,0.06)';
  ctx.lineWidth = 14;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Zones
  const zones = [
    { from: 0, to: 0.3, color: '#00e676' },
    { from: 0.3, to: 0.6, color: '#ffb800' },
    { from: 0.6, to: 1.0, color: '#ff3a3a' }
  ];

  zones.forEach(z => {
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle + z.from * Math.PI, startAngle + z.to * Math.PI);
    ctx.strokeStyle = z.color + '44';
    ctx.lineWidth = 14;
    ctx.stroke();
  });

  // Animated fill
  let current = 0;
  function animGauge() {
    if (current >= value) return;
    current = Math.min(current + 1.5, value);
    const ang = startAngle + (current / 100) * Math.PI;

    ctx.clearRect(0, 0, W, H);

    // Redraw track
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, endAngle);
    ctx.strokeStyle = 'rgba(255,255,255,0.06)';
    ctx.lineWidth = 14;
    ctx.stroke();

    zones.forEach(z => {
      ctx.beginPath();
      ctx.arc(cx, cy, r, startAngle + z.from * Math.PI, startAngle + z.to * Math.PI);
      ctx.strokeStyle = z.color + '44';
      ctx.lineWidth = 14;
      ctx.stroke();
    });

    // Value arc
    const gradient = ctx.createLinearGradient(0, cy, W, cy);
    gradient.addColorStop(0, '#00e676');
    gradient.addColorStop(0.5, '#ffb800');
    gradient.addColorStop(1, '#ff3a3a');

    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, ang);
    ctx.strokeStyle = gradient;
    ctx.lineWidth = 14;
    ctx.lineCap = 'round';
    ctx.shadowBlur = 16;
    ctx.shadowColor = '#ff3a3a';
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Needle
    const nx = cx + (r - 7) * Math.cos(ang);
    const ny = cy + (r - 7) * Math.sin(ang);
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(nx, ny);
    ctx.strokeStyle = '#fff';
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(cx, cy, 5, 0, Math.PI * 2);
    ctx.fillStyle = '#fff';
    ctx.fill();

    requestAnimationFrame(animGauge);
  }

  animGauge();
}

// ─── Live Activity Feed ───────────────────────────────────────────────────────

function startActivityFeed() {
  const feed = document.getElementById('activityFeed');
  const liveItems = [
    { cls: 'info-item', icon: '🔵', text: 'Hash computed: <code>d91bc4...22fe</code> — 0 VT matches' },
    { cls: 'warning-item', icon: '🟡', text: 'Hidden file detected: <code>.sysconfig</code>' },
    { cls: 'critical-item', icon: '🔴', text: 'Malicious IP contact: <code>185.220.101.45</code>' },
    { cls: 'info-item', icon: '🔵', text: 'Registry scan complete — 12 entries analyzed' },
    { cls: 'warning-item', icon: '🟡', text: 'Deleted file recovered: <code>keylog_output.log</code>' },
    { cls: 'critical-item', icon: '🔴', text: 'Autorun entry confirmed — persistence mechanism found' },
  ];

  let idx = 0;
  setInterval(() => {
    const item = liveItems[idx % liveItems.length];
    const now = new Date();
    const time = now.toTimeString().substring(0, 8);

    const el = document.createElement('div');
    el.className = `activity-item ${item.cls}`;
    el.innerHTML = `
      <span class="act-time">${time}</span>
      <span class="act-icon">${item.icon}</span>
      <span class="act-text">${item.text}</span>
    `;

    el.style.opacity = '0';
    el.style.transform = 'translateY(-10px)';
    feed.insertBefore(el, feed.firstChild);

    setTimeout(() => {
      el.style.transition = 'all 0.4s ease';
      el.style.opacity = '1';
      el.style.transform = 'translateY(0)';
    }, 10);

    // Remove overflow items
    while (feed.children.length > 10) {
      feed.removeChild(feed.lastChild);
    }

    idx++;
  }, 5000);
}

// ─── Evidence Import Simulation ───────────────────────────────────────────────

function simulateImport() {
  const progress = document.getElementById('importProgress');
  const fill = document.getElementById('progressFill');
  const pct = document.getElementById('progPct');
  const steps = ['step1', 'step2', 'step3', 'step4', 'step5'];

  progress.style.display = 'block';

  let value = 0;
  let stepIdx = 0;

  steps.forEach(s => {
    document.getElementById(s).className = 'prog-step';
  });
  document.getElementById(steps[0]).classList.add('active');

  const interval = setInterval(() => {
    value += Math.random() * 3 + 1;
    if (value > 100) value = 100;

    fill.style.width = value + '%';
    pct.textContent = Math.floor(value) + '%';

    const newStep = Math.floor(value / 20);
    if (newStep > stepIdx && newStep < steps.length) {
      document.getElementById(steps[stepIdx]).className = 'prog-step done';
      stepIdx = newStep;
      document.getElementById(steps[stepIdx]).classList.add('active');
    }

    if (value >= 100) {
      clearInterval(interval);
      steps.forEach(s => document.getElementById(s).className = 'prog-step done');
      pct.textContent = '100%';
      setTimeout(() => showToast('✓ EVIDENCE IMAGE PROCESSED — 3,847 artifacts extracted'), 300);
    }
  }, 120);
}

function handleDrop(e) {
  e.preventDefault();
  simulateImport();
}

// ─── Artifact Filtering ───────────────────────────────────────────────────────

function filterArtifacts(type, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  document.querySelectorAll('.artifact-row').forEach(row => {
    if (type === 'all' || row.dataset.type === type) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
}

// ─── Export Simulation ────────────────────────────────────────────────────────

function simulateExport(format) {
  showToast(`✓ ${format} REPORT GENERATED — CTF-2025-001_report.${format.toLowerCase()}`);
}

function showToast(msg) {
  const toast = document.getElementById('exportToast');
  if (!toast) return;
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 4000);
}

// ─── Window Resize: Redraw Canvases ──────────────────────────────────────────

window.addEventListener('resize', () => {
  drawThreatMap();
});
