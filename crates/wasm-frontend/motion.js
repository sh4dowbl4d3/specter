(() => {
  const boot = () => {
    if (window.__specterMotionBooted || !window.gsap) return;
    window.__specterMotionBooted = true;
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
      const amethyst = new THREE.Color('#7c3aed');
      const lavender = new THREE.Color('#a78bfa');

      for (let i = 0; i < count; i += 1) {
        const angle = i * 0.43;
        const radius = 1.45 + (i % 17) * 0.075;
        const y = ((i % 46) - 23) * 0.105;
        positions[i * 3] = Math.cos(angle) * radius;
        positions[i * 3 + 1] = y + Math.sin(angle * 0.7) * 0.32;
        positions[i * 3 + 2] = Math.sin(angle) * radius * 0.52;
        const c = i % 4 === 0 ? amethyst : lavender;
        colors[i * 3] = c.r;
        colors[i * 3 + 1] = c.g;
        colors[i * 3 + 2] = c.b;
      }

      const geometry = new THREE.BufferGeometry();
      geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
      geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));
      const material = new THREE.PointsMaterial({
        size: 0.026,
        vertexColors: true,
        transparent: true,
        opacity: 0.85,
        blending: THREE.AdditiveBlending,
        depthWrite: false
      });
      const points = new THREE.Points(geometry, material);
      scene.add(points);

      const ring = new THREE.Mesh(
        new THREE.TorusGeometry(2.08, 0.008, 8, 100),
        new THREE.MeshBasicMaterial({ color: 0x7c3aed, transparent: true, opacity: 0.35 })
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

    const intro = gsap.timeline({ defaults: { duration: 0.7 } });
    intro
      .from('.site-header', { y: -12, autoAlpha: 0 })
      .from('.hero-kicker', { autoAlpha: 0, duration: 0.4 }, '-=0.3')
      .from('.hero h1', { y: 16, autoAlpha: 0, duration: 0.6 }, '-=0.3')
      .from('.hero-deck, .hero-aside', { y: 16, autoAlpha: 0, stagger: 0.1 }, '-=0.3')
      .from('.signal-strip', { y: 16, autoAlpha: 0, duration: 0.5 }, '-=0.2');
  };

  const waitForLibraries = () => {
    if (window.gsap) { boot(); return; }
    if (!window.__specterMotionWaits) window.__specterMotionWaits = 0;
    window.__specterMotionWaits += 1;
    if (window.__specterMotionWaits === 1) document.documentElement.classList.add('motion-fallback');
    if (window.__specterMotionWaits < 80) window.setTimeout(waitForLibraries, 100);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', waitForLibraries, { once: true });
  else waitForLibraries();
})();