import './style.css';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';

gsap.registerPlugin(ScrollTrigger);

/* ---------- Three.js (code-split) ---------- */
const heroCanvas = document.getElementById('hero-canvas');
if (heroCanvas) {
  import('./three-scene.js').then(({ initHeroScene }) => {
    initHeroScene(heroCanvas);
  });
}

/* ---------- Toast ---------- */
let toastTimer;
window.showToast = function (msg) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2200);
};

/* ---------- Copy ---------- */
document.querySelectorAll('.cpy').forEach((b) => {
  b.addEventListener('click', () => {
    const e = document.getElementById(b.dataset.target);
    if (!e) return;
    const t = e.textContent;
    if (!t || !t.trim()) return;
    navigator.clipboard.writeText(t).then(() => {
      b.textContent = 'Copied';
      window.showToast('Copied');
      setTimeout(() => { b.textContent = 'Copy'; }, 1200);
    });
  });
});

/* ---------- FAQ ---------- */
document.querySelectorAll('.fi').forEach((el) => {
  el.addEventListener('click', function () { this.classList.toggle('open'); });
});

/* ---------- Cipher params ---------- */
const ct = document.getElementById('cipher-type');
const cpg = document.getElementById('cipher-param-group');
const cpi = document.getElementById('cipher-param');
if (ct) {
  ct.addEventListener('change', () => {
    const v = ct.value;
    cpg.style.display = v === 'caesar' || v === 'vigenere' ? 'flex' : 'none';
    cpi.placeholder = v === 'caesar' ? 'Shift (0-25)' : 'Key phrase';
  });
}

/* ---------- API ---------- */
const API = '';
async function api(e, d) {
  const r = await fetch(API + e, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d),
  });
  return r.json();
}
function load(el) { el.innerHTML = '<span class="ld"></span><span style="opacity:0.5">Processing</span>'; }
function done(el, d) {
  const j = JSON.stringify(d, null, 2);
  el.innerHTML = j.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function fail(el, m) { el.innerHTML = '<span class="err">' + m + '</span>'; }
function show(id) { document.getElementById(id).classList.add('open'); }

window.identifyHash = async function () {
  const h = document.getElementById('hash-input').value.trim();
  if (!h) return;
  show('hash-output');
  const o = document.getElementById('hash-output-body');
  load(o);
  try {
    const d = await api('/api/hash/identify', { hash: h });
    if (!d || !d.length) { o.innerHTML = '<span style="opacity:0.5;font-style:italic">No matches</span>'; return; }
    let html = '<table class="rt"><thead><tr><th>Type</th><th>Conf</th><th>Len</th><th>Charset</th></tr></thead><tbody>';
    for (const r of d) html += '<tr><td class="ky">' + (r.hash_type || 'Unknown') + '</td><td>' + (r.confidence * 100).toFixed(0) + '%</td><td>' + r.length + '</td><td>' + r.charset + '</td></tr>';
    html += '</tbody></table>';
    o.innerHTML = html;
  } catch (e) { fail(o, 'Request failed'); }
};
window.crackHash = async function () {
  const h = document.getElementById('hash-input').value.trim();
  if (!h) return;
  const w = document.getElementById('wordlist-input').value.trim() || null;
  show('crack-output');
  const o = document.getElementById('crack-output-body');
  load(o);
  try { const d = await api('/api/hash/crack', { hash: h, wordlist_path: w }); done(o, d); } catch (e) { fail(o, 'Request failed'); }
};
window.bruteForce = async function () {
  const h = document.getElementById('hash-input').value.trim();
  if (!h) return;
  const l = parseInt(document.getElementById('bf-maxlen').value);
  const c = document.getElementById('bf-charset').value;
  show('crack-output');
  const o = document.getElementById('crack-output-body');
  load(o);
  try { const d = await api('/api/hash/bruteforce', { hash: h, max_length: l, charset: c }); done(o, d); } catch (e) { fail(o, 'Request failed'); }
};
window.cipherDecode = async function () {
  const t = document.getElementById('cipher-text').value.trim();
  if (!t) return;
  const c = document.getElementById('cipher-type').value;
  const p = document.getElementById('cipher-param').value.trim();
  show('cipher-output');
  const o = document.getElementById('cipher-output-body');
  load(o);
  try {
    const b = { text: t };
    if (c !== 'auto') b.cipher = c;
    if (c === 'caesar') b.shift = parseInt(p) || 0;
    if (c === 'vigenere') b.key = p;
    const d = await api('/api/cipher/decode', b); done(o, d);
  } catch (e) { fail(o, 'Request failed'); }
};
window.cipherEncode = async function () {
  const t = document.getElementById('cipher-text').value.trim();
  if (!t) return;
  const c = document.getElementById('cipher-type').value;
  if (c === 'auto') { fail(document.getElementById('cipher-output-body'), 'Select a specific cipher'); return; }
  const p = document.getElementById('cipher-param').value.trim();
  show('cipher-output');
  const o = document.getElementById('cipher-output-body');
  load(o);
  try {
    const b = { text: t, cipher: c };
    if (c === 'caesar') b.shift = parseInt(p) || 0;
    if (c === 'vigenere') b.key = p;
    const d = await api('/api/cipher/encode', b); done(o, d);
  } catch (e) { fail(o, 'Request failed'); }
};
window.cipherDetect = async function () {
  const t = document.getElementById('cipher-text').value.trim();
  if (!t) return;
  show('cipher-output');
  const o = document.getElementById('cipher-output-body');
  load(o);
  try {
    const d = await api('/api/cipher/detect', { text: t });
    if (!d || !d.length) { o.innerHTML = '<span style="opacity:0.5;font-style:italic">No matches</span>'; return; }
    let html = '<table class="rt"><thead><tr><th>Cipher</th><th>Conf</th><th>Decoded</th></tr></thead><tbody>';
    for (const r of d) {
      const pv = r.decoded ? r.decoded.substring(0, 100) + (r.decoded.length > 100 ? '...' : '') : '-';
      html += '<tr><td class="ky">' + (r.cipher_type || 'Unknown') + '</td><td>' + (r.confidence * 100).toFixed(0) + '%</td><td>' + pv + '</td></tr>';
    }
    html += '</tbody></table>';
    o.innerHTML = html;
  } catch (e) { fail(o, 'Request failed'); }
};

document.getElementById('hash-input')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) window.identifyHash();
});
document.getElementById('cipher-text')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) window.cipherDecode();
});

/* ---------- GSAP Entry ---------- */
gsap.fromTo('.hero-left', { y: 40, opacity: 0 }, {
  y: 0, opacity: 1, duration: 1, ease: 'power4.out', delay: 0.1,
});
gsap.fromTo('.hero-headline .italic', { opacity: 0 }, {
  opacity: 1, duration: 0.6, delay: 0.6,
});
gsap.fromTo('.hero-sub', { y: 16, opacity: 0 }, {
  y: 0, opacity: 1, duration: 0.7, ease: 'power3.out', delay: 0.5,
});
gsap.fromTo('.hero-ticker', { y: -8, opacity: 0 }, {
  y: 0, opacity: 1, duration: 0.5, delay: 0.2,
});

/* Nav only on hero — fades as hero scrolls past */
gsap.to('.nav', {
  opacity: 0, duration: 0.4, ease: 'power2.out',
  scrollTrigger: {
    trigger: '.hero',
    start: 'bottom 80%',
    end: 'bottom top',
    scrub: 0.5,
  },
});

function reveal(sel, extra) {
  gsap.fromTo(sel, { y: 20, opacity: 0 }, {
    y: 0, opacity: 1, duration: 0.7, ease: 'power3.out',
    scrollTrigger: { trigger: sel, start: 'top 85%', once: true },
    ...extra,
  });
}
reveal('.editorial');
reveal('.tc-grid', { stagger: 0.08 });
reveal('.ag', { delay: 0.1 });
reveal('.cs', { stagger: 0.06 });
reveal('.fl', { delay: 0.1 });
gsap.fromTo('footer', { y: 12, opacity: 0 }, {
  y: 0, opacity: 1, duration: 0.5,
  scrollTrigger: { trigger: 'footer', start: 'top 90%', once: true },
});

/* ---------- GSAP Hover Effects ---------- */
const isTouch = !window.matchMedia('(hover: hover)').matches;
if (!isTouch) {

  /* Cards tilt */
  document.querySelectorAll('.tc, .ac, .cc').forEach((el) => {
    el.addEventListener('mousemove', (e) => {
      const rect = el.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width - 0.5;
      const y = (e.clientY - rect.top) / rect.height - 0.5;
      gsap.to(el, {
        rotationX: -y * 4,
        rotationY: x * 4,
        transformPerspective: 800,
        duration: 0.4,
        ease: 'power2.out',
        overwrite: 'auto',
      });
    });
    el.addEventListener('mouseleave', () => {
      gsap.to(el, {
        rotationX: 0, rotationY: 0,
        duration: 0.4, ease: 'power2.out', overwrite: 'auto',
      });
    });
  });

  /* Nav link subtle parallax */
  document.querySelectorAll('.nav-link').forEach((el) => {
    el.addEventListener('mouseenter', () => {
      gsap.to(el, { x: 4, duration: 0.3, ease: 'power2.out' });
    });
    el.addEventListener('mouseleave', () => {
      gsap.to(el, { x: 0, duration: 0.3, ease: 'power2.out' });
    });
  });

  /* Footer link hover */
  document.querySelectorAll('.footer-col a').forEach((el) => {
    el.addEventListener('mouseenter', () => {
      gsap.to(el, { x: 4, duration: 0.2, ease: 'power1.out' });
    });
    el.addEventListener('mouseleave', () => {
      gsap.to(el, { x: 0, duration: 0.2, ease: 'power1.out' });
    });
  });

  /* FAQ hover */
  document.querySelectorAll('.fi').forEach((el) => {
    el.addEventListener('mouseenter', () => {
      gsap.to(el.querySelector('.ft'), { rotation: 90, duration: 0.3, ease: 'back.out(1.7)', overwrite: 'auto' });
    });
    el.addEventListener('mouseleave', () => {
      if (!el.classList.contains('open')) {
        gsap.to(el.querySelector('.ft'), { rotation: 0, duration: 0.3, ease: 'power2.out', overwrite: 'auto' });
      }
    });
  });
}
