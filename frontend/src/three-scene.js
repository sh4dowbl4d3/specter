import * as THREE from 'three';

export function initHeroScene(container) {
  const scene = new THREE.Scene();
  const w = container.clientWidth;
  const h = container.clientHeight;

  const camera = new THREE.PerspectiveCamera(40, w / h, 0.1, 100);
  camera.position.set(0, 0, 8);

  const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: false });
  renderer.setSize(w, h);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
  renderer.setClearColor(0x000000, 0);
  container.appendChild(renderer.domElement);

  const shape = new THREE.Mesh(
    new THREE.IcosahedronGeometry(2.8, 0),
    new THREE.MeshStandardMaterial({
      color: 0x2a2722,
      metalness: 0,
      roughness: 0.8,
      transparent: true,
      opacity: 0.06,
      wireframe: false,
    })
  );
  scene.add(shape);

  const wire = new THREE.Mesh(
    new THREE.IcosahedronGeometry(2.8, 1),
    new THREE.MeshBasicMaterial({
      color: 0x2a2722,
      wireframe: true,
      transparent: true,
      opacity: 0.08,
    })
  );
  scene.add(wire);

  const count = 120;
  const pos = new Float32Array(count * 3);
  for (let i = 0; i < count; i++) {
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    const r = 3.5 + Math.random() * 4;
    pos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
    pos[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
    pos[i * 3 + 2] = r * Math.cos(phi);
  }
  const pgeo = new THREE.BufferGeometry();
  pgeo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
  const pmat = new THREE.PointsMaterial({
    color: 0x2a2722,
    size: 0.025,
    transparent: true,
    opacity: 0.12,
    blending: THREE.AdditiveBlending,
    sizeAttenuation: true,
  });
  const pts = new THREE.Points(pgeo, pmat);
  scene.add(pts);

  let mx = 0, my = 0, tx = 0, ty = 0;
  const onMove = (e) => {
    tx = (e.clientX / window.innerWidth) * 2 - 1;
    ty = -(e.clientY / window.innerHeight) * 2 + 1;
  };
  if (window.matchMedia('(hover: hover)').matches) {
    window.addEventListener('mousemove', onMove);
  }

  const onResize = () => {
    const cw = container.clientWidth, ch = container.clientHeight;
    camera.aspect = cw / ch;
    camera.updateProjectionMatrix();
    renderer.setSize(cw, ch);
  };
  window.addEventListener('resize', onResize);

  let t = 0;
  function animate() {
    t += 0.006;
    mx += (tx - mx) * 0.05;
    my += (ty - my) * 0.05;

    shape.rotation.x = t * 0.12 + my * 0.15;
    shape.rotation.y = t * 0.15 + mx * 0.15;
    wire.rotation.x = shape.rotation.x;
    wire.rotation.y = shape.rotation.y;
    wire.rotation.z = t * 0.06;
    pts.rotation.x = t * 0.01;
    pts.rotation.y = t * 0.02;

    renderer.render(scene, camera);
    requestAnimationFrame(animate);
  }
  animate();

  return {
    destroy: () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('resize', onResize);
      renderer.dispose();
      container.removeChild(renderer.domElement);
    },
  };
}
