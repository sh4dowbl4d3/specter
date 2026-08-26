(() => {
  const boot = () => {
    if (window.__devastatorMotionBooted || !window.gsap) return;
    window.__devastatorMotionBooted = true;
    document.documentElement.classList.remove('motion-fallback');
    const { gsap, THREE } = window;
    if (window.ScrollTrigger) gsap.registerPlugin(window.ScrollTrigger);

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const canvas = document.querySelector('#cipher-canvas');

    if (canvas && !reduceMotion && THREE) {
      try {
      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(44, 1, 0.1, 100);
      camera.position.z = 7;

      const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.6));
      renderer.setClearColor(0x000000, 0);

      const count = 520;
      const positions = new Float32Array(count * 3);
      const colors = new Float32Array(count * 3);
      const green = new THREE.Color('#2bee4b');
      const sage = new THREE.Color('#93b799');

      for (let i = 0; i < count; i += 1) {
        const angle = i * 0.43;
        const radius = 1.45 + (i % 17) * 0.075;
        const y = ((i % 46) - 23) * 0.105;
        positions[i * 3] = Math.cos(angle) * radius;
        positions[i * 3 + 1] = y + Math.sin(angle * 0.7) * 0.32;
        positions[i * 3 + 2] = Math.sin(angle) * radius * 0.52;
        const c = i % 5 === 0 ? green : sage;
        colors[i * 3] = c.r;
        colors[i * 3 + 1] = c.g;
        colors[i * 3 + 2] = c.b;
      }

      const geometry = new THREE.BufferGeometry();
      geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
      geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));
      const material = new THREE.PointsMaterial({
        size: 0.025,
        vertexColors: true,
        transparent: true,
        opacity: 0.76,
        blending: THREE.AdditiveBlending,
        depthWrite: false
      });
      const points = new THREE.Points(geometry, material);
      scene.add(points);

      const ring = new THREE.Mesh(
        new THREE.TorusGeometry(2.08, 0.008, 8, 100),
        new THREE.MeshBasicMaterial({ color: 0x2bee4b, transparent: true, opacity: 0.22 })
      );
      ring.rotation.x = Math.PI * 0.45;
      ring.rotation.y = Math.PI * 0.14;
      scene.add(ring);

      const resize = () => {
        const rect = canvas.parentElement.getBoundingClientRect();
        renderer.setSize(rect.width, rect.height, false);
        camera.aspect = rect.width / Math.max(rect.height, 1);
        camera.updateProjectionMatrix();
      };
      resize();
      window.addEventListener('resize', resize, { passive: true });

      const pointer = { x: 0, y: 0 };
      window.addEventListener('pointermove', (event) => {
        pointer.x = (event.clientX / window.innerWidth - 0.5) * 0.7;
        pointer.y = (event.clientY / window.innerHeight - 0.5) * 0.35;
      }, { passive: true });

      const clock = new THREE.Clock();
      const render = () => {
        const elapsed = clock.getElapsedTime();
        points.rotation.y = elapsed * 0.08 + pointer.x * 0.2;
        points.rotation.x = Math.sin(elapsed * 0.2) * 0.08 + pointer.y * 0.12;
        ring.rotation.z = elapsed * 0.11;
        renderer.render(scene, camera);
        requestAnimationFrame(render);
      };
      render();
      } catch (error) {
        canvas.style.display = 'none';
        console.warn('Three.js canvas disabled:', error);
      }
    }

    if (reduceMotion) {
      document.documentElement.classList.add('reduced-motion');
      return;
    }

    document.documentElement.classList.add('motion-ready');
    gsap.defaults({ ease: 'power3.out' });

    const intro = gsap.timeline({ defaults: { duration: 0.8 } });
    intro
      .from('.site-header', { y: -18, autoAlpha: 0 })
      .from('.hero-kicker > *', { y: 12, autoAlpha: 0, stagger: 0.06 }, '-=0.45')
      .from('.hero h1 > *', { yPercent: 110, autoAlpha: 0, stagger: 0.12, duration: 1.05 }, '-=0.35')
      .from('.hero-deck, .hero-plate, .hero-aside', { y: 24, autoAlpha: 0, stagger: 0.12 }, '-=0.5')
      .from('.signal-strip > *', { y: 18, autoAlpha: 0, stagger: 0.08 }, '-=0.35');

    if (window.ScrollTrigger) {
      gsap.to('.hero h1', {
        yPercent: -12,
        rotation: -1,
        ease: 'none',
        scrollTrigger: { trigger: '.hero', start: 'top top', end: 'bottom top', scrub: 1 }
      });
      gsap.to('.hero-plate', {
        y: -50,
        rotation: 3,
        ease: 'none',
        scrollTrigger: { trigger: '.hero', start: 'top top', end: 'bottom top', scrub: 1 }
      });
      gsap.from('.workspace-head, #tabs', {
        y: 34,
        autoAlpha: 0,
        stagger: 0.12,
        scrollTrigger: { trigger: '.workspace', start: 'top 78%', once: true }
      });
      gsap.from('.dark-note > *', {
        y: 28,
        autoAlpha: 0,
        stagger: 0.1,
        scrollTrigger: { trigger: '.dark-note', start: 'top 78%', once: true }
      });
      gsap.from('.footer-credit', {
        xPercent: -20,
        autoAlpha: 0,
        duration: 1.1,
        scrollTrigger: { trigger: '.footer-credit', start: 'top 90%', once: true }
      });
    }

    const animatePanel = (panel) => {
      if (!panel) return;
      gsap.fromTo(panel.querySelectorAll('.section-index, .form-col h3, .lead, .form-col label, .form-col textarea, .form-col select, .form-col .dropzone, .form-col .actions, .output, .result-caption'),
        { y: 20, autoAlpha: 0 },
        { y: 0, autoAlpha: 1, duration: 0.55, stagger: 0.035, overwrite: 'auto' }
      );
    };

    document.querySelectorAll('#tabs button').forEach((button) => {
      button.addEventListener('click', () => {
        window.requestAnimationFrame(() => animatePanel(document.querySelector('#tab-' + button.dataset.tab)));
      });
    });
  };

  const waitForLibraries = () => {
    if (window.gsap) { boot(); return; }
    if (!window.__devastatorMotionWaits) window.__devastatorMotionWaits = 0;
    window.__devastatorMotionWaits += 1;
    if (window.__devastatorMotionWaits === 1) document.documentElement.classList.add('motion-fallback');
    if (window.__devastatorMotionWaits < 80) window.setTimeout(waitForLibraries, 100);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', waitForLibraries, { once: true });
  else waitForLibraries();
})();