(() => {
  'use strict';
  const widget = document.getElementById('captcha-widget');
  if (!widget) return;
  const stage = document.getElementById('captcha-stage');
  const master = document.getElementById('captcha-master');
  const tile = document.getElementById('captcha-tile');
  const status = document.getElementById('captcha-status');
  const refresh = document.getElementById('captcha-load');
  const verify = document.getElementById('captcha-verify');
  const useCaptcha = document.getElementById('use-captcha');
  let challenge = null, left = 0, top = 0, busy = false, ready = false, drag = null;
  const form = document.getElementById('login-form');
  const password = document.getElementById('password');
  const email = document.getElementById('email');
  const signButton = document.getElementById('login-submit');
  const loginError = document.getElementById('login-error');
  const panel = document.getElementById('verification-panel');
  const layout = panel.parentElement;
  let signingIn = false;
  let navigating = false;
  document.getElementById('password-toggle').addEventListener('click', event => {
    const visible = password.type === 'password';
    password.type = visible ? 'text' : 'password';
    event.currentTarget.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
    event.currentTarget.setAttribute('title', visible ? 'Hide password' : 'Show password');
    event.currentTarget.setAttribute('aria-pressed', String(visible));
  });
  async function signIn() {
    if (signingIn || !form.reportValidity()) return;
    signingIn = true; signButton.disabled = true; signButton.textContent = 'Signing in…';
    refresh.disabled = true; verify.disabled = true;
    loginError.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 120000);
    try {
      const response = await fetch('login.php', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'X-Requested-With': 'LoginForm', 'Accept': 'application/json' },
        body: new FormData(form), signal: controller.signal,
      });
      const result = await response.json();
      if (result.ok) {
        // Keep the field intact until this document is replaced by the dashboard.
        window.location.assign('index.php');
        navigating = true;
        return;
      }
      loginError.textContent = result.message || 'Could not sign in. Please try again.';
      loginError.hidden = false;
      if (result.csrf) {
        form.querySelector('[name="csrf"]').value = result.csrf;
        widget.dataset.csrf = result.csrf;
      }
      useCaptcha.value = '0';
      panel.hidden = !result.captcha;
      widget.dataset.active = result.captcha ? '1' : '0';
      layout.classList.toggle('has-captcha', Boolean(result.captcha));
      if (result.captcha) {
        // The original password field stays mounted: no server-side/password storage.
        await load();
        panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    } catch (error) {
      loginError.textContent = error.name === 'AbortError'
        ? 'Sign-in timed out. Please try again.' : 'Could not sign in. Please try again.';
      loginError.hidden = false;
    } finally {
      clearTimeout(timer);
      if (!navigating) {
        signingIn = false;
        signButton.disabled = false; signButton.textContent = 'Sign in'; controls();
      }
    }
  }
  form.addEventListener('submit', event => { event.preventDefault(); if (!busy) signIn(); });
  email.addEventListener('input', () => { useCaptcha.value = '0'; });


  function controls() {
    refresh.disabled = busy || signingIn;
    verify.disabled = busy || signingIn || !ready;
    tile.style.pointerEvents = busy || signingIn || !ready ? 'none' : 'auto';
  }
  function paint() {
    tile.style.left = `${100 * left / challenge.master_width}%`;
    tile.style.top = `${100 * top / challenge.master_height}%`;
  }
  function position(x, y) {
    left = Math.max(0, Math.min(challenge.master_width - challenge.tile_width, x));
    top = Math.max(0, Math.min(challenge.master_height - challenge.tile_height, y));
    paint();
  }
  async function request(action, extra = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch('image.php', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        body: new URLSearchParams({ action, csrf: widget.dataset.csrf, ...extra }),
        signal: controller.signal,
      });
      const result = await response.json();
      if (result.session_expired) {
        useCaptcha.value = '0'; challenge = null; ready = false;
        if (result.csrf) {
          form.querySelector('[name="csrf"]').value = result.csrf;
          widget.dataset.csrf = result.csrf;
        }
      }
      if (!response.ok || !result.ok) throw new Error(result.message || 'The challenge request failed.');
      return result;
    } finally { clearTimeout(timer); }
  }
  function imageReady(image) {
    return new Promise((resolve, reject) => {
      if (image.complete) return image.naturalWidth ? resolve() : reject(new Error('Challenge image could not load.'));
      const timer = setTimeout(() => finish(new Error('Challenge image timed out. Use the official-site link.')), 15000);
      function finish(error) {
        clearTimeout(timer); image.onload = null; image.onerror = null;
        if (error) reject(error); else resolve();
      }
      image.onload = () => finish();
      image.onerror = () => finish(new Error('Challenge image could not load. Use the official-site link if it continues.'));
    });
  }
  async function load() {
    if (busy) return;
    busy = true; ready = false; challenge = null; drag = null; useCaptcha.value = '0';
    controls(); stage.hidden = true; status.textContent = 'Loading challenge…';
    try {
      const result = await request('load');
      challenge = result.challenge;
      left = challenge.tile_x; top = challenge.tile_y;
      stage.style.aspectRatio = `${challenge.master_width} / ${challenge.master_height}`;
      tile.style.width = `${100 * challenge.tile_width / challenge.master_width}%`;
      tile.style.height = `${100 * challenge.tile_height / challenge.master_height}%`;
      paint();
      master.src = challenge.master_image;
      tile.src = challenge.tile_image;
      await Promise.all([imageReady(master), imageReady(tile)]);
      stage.hidden = false; ready = true;
      status.textContent = 'Drag the piece into place and release. You can also use arrow keys and Enter on the piece.';
    } catch (error) {
      status.textContent = error.name === 'AbortError' ? 'Request timed out. Load another challenge.' : error.message;
    } finally { busy = false; controls(); }
  }
  async function submit() {
    if (busy || !ready || !challenge) return;
    busy = true; ready = false; controls(); status.textContent = 'Checking your placement…';
    try {
      const result = await request('verify', {
        delta_x: String(Math.round(left - challenge.tile_x)),
        delta_y: String(Math.round(top - challenge.tile_y)),
      });
      useCaptcha.value = '1';
      status.textContent = result.message;
      if (widget.dataset.autoSubmit === '1' && password.value !== '' && email.value !== '') {
        status.textContent = 'Verification accepted. Signing in…';
        busy = false;
        await signIn();
      } else {
        status.textContent = 'Verification accepted. Enter your password and click Sign in.';
        password.focus();
      }
    } catch (error) {
      useCaptcha.value = '0';
      status.textContent = error.name === 'AbortError' ? 'Verification timed out. Load another challenge.' : error.message;
    } finally { busy = false; controls(); }
  }
  tile.addEventListener('pointerdown', event => {
    if (busy || !ready || !event.isPrimary || event.button !== 0) return;
    event.preventDefault(); tile.focus();
    drag = { id: event.pointerId, x: event.clientX, y: event.clientY, left, top };
    tile.setPointerCapture(event.pointerId); tile.classList.add('dragging');
  });
  tile.addEventListener('pointermove', event => {
    if (!drag || drag.id !== event.pointerId) return;
    const scale = stage.getBoundingClientRect().width / challenge.master_width;
    if (scale <= 0) return;
    position(drag.left + (event.clientX - drag.x) / scale, drag.top + (event.clientY - drag.y) / scale);
  });
  tile.addEventListener('pointerup', event => {
    if (!drag || drag.id !== event.pointerId) return;
    const moved = Math.hypot(event.clientX - drag.x, event.clientY - drag.y) >= 2;
    drag = null; tile.classList.remove('dragging');
    if (tile.hasPointerCapture(event.pointerId)) tile.releasePointerCapture(event.pointerId);
    if (moved) submit();
  });
  function cancelDrag() { drag = null; tile.classList.remove('dragging'); }
  tile.addEventListener('pointercancel', cancelDrag);
  tile.addEventListener('lostpointercapture', cancelDrag);
  tile.addEventListener('keydown', event => {
    if (busy || !ready || !challenge) return;
    const amount = event.shiftKey ? 10 : 1;
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); submit(); return; }
    const offsets = { ArrowLeft: [-amount, 0], ArrowRight: [amount, 0], ArrowUp: [0, -amount], ArrowDown: [0, amount] };
    if (offsets[event.key]) { event.preventDefault(); position(left + offsets[event.key][0], top + offsets[event.key][1]); }
  });
  refresh.addEventListener('click', load);
  verify.addEventListener('click', submit);
  if (widget.dataset.active === '1') load();
})();
