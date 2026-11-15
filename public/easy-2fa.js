/*
 * Two-Factor Sign-In Client
 *
 * Challenge method switch, passkey sign-in and registration, recovery code saving.
 *
 * Authors:
 * MoyuZJ <moyuzj@evarentha.com> @LinearTeam - Made in China with ♥
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
(() => {
  const LP = window.LinearPress;
  const b64uToBytes = (value) => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const bytesToB64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const say = (message) => (LP?.toast ? LP.toast(message, 'danger') : window.alert(message));
  const cancelled = (error) => error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'AbortError');

  /* challenge: switch between authenticator code and recovery code */
  document.querySelectorAll('[data-e2fa-switch]').forEach((button) => button.addEventListener('click', () => {
    const target = button.dataset.e2faSwitch;
    document.querySelectorAll('[data-e2fa-panel]').forEach((panel) => { panel.hidden = panel.dataset.e2faPanel !== target; });
    document.querySelectorAll('[data-e2fa-switch]').forEach((other) => { other.hidden = other.dataset.e2faSwitch === target; });
    document.querySelector(`[data-e2fa-panel="${target}"] input[name=code]`)?.focus();
  }));
  // Six digits entered: submit straight away.
  document.querySelectorAll('[data-e2fa-panel="totp"] input[name=code]').forEach((input) => input.addEventListener('input', () => {
    if (/^\d{6}$/.test(input.value.replace(/\s/g, ''))) input.form.requestSubmit();
  }));

  /* passkey as the second step */
  document.querySelectorAll('[data-e2fa-passkey-login]').forEach((button) => button.addEventListener('click', async () => {
    if (!window.PublicKeyCredential) return say('这个浏览器不支持通行密钥');
    button.disabled = true;
    try {
      const optionsResponse = await fetch(button.dataset.optionsUrl, { headers: { accept: 'application/json' } });
      const options = await optionsResponse.json();
      if (!optionsResponse.ok) throw new Error(options.message || '无法开始验证');
      const credential = await navigator.credentials.get({ publicKey: { challenge: b64uToBytes(options.challenge), rpId: options.rpId, timeout: options.timeout || 60000, userVerification: options.userVerification || 'preferred', allowCredentials: (options.allowCredentials || []).map((d) => ({ id: b64uToBytes(d.id), type: d.type })) } });
      const data = await LP.postJson(button.dataset.verifyUrl, { id: credential.id, response: { clientDataJSON: bytesToB64u(credential.response.clientDataJSON), authenticatorData: bytesToB64u(credential.response.authenticatorData), signature: bytesToB64u(credential.response.signature) } });
      location.assign(data.redirect);
    } catch (error) { if (!cancelled(error)) say(error.message || '通行密钥验证失败'); button.disabled = false; }
  }));

  /* register a passkey on the account page */
  document.querySelectorAll('[data-e2fa-passkey-register]').forEach((button) => button.addEventListener('click', async () => {
    if (!window.PublicKeyCredential) return say('这个浏览器不支持通行密钥');
    button.disabled = true;
    try {
      const optionsResponse = await fetch(button.dataset.optionsUrl, { headers: { accept: 'application/json' } });
      const options = await optionsResponse.json();
      if (!optionsResponse.ok) throw new Error(options.message || '无法开始注册');
      const credential = await navigator.credentials.create({ publicKey: { ...options, challenge: b64uToBytes(options.challenge), user: { ...options.user, id: b64uToBytes(options.user.id) }, excludeCredentials: (options.excludeCredentials || []).map((d) => ({ id: b64uToBytes(d.id), type: d.type })) } });
      const name = navigator.userAgentData?.platform || (/iPhone|iPad/.test(navigator.userAgent) ? 'iPhone / iPad' : /Android/.test(navigator.userAgent) ? 'Android 设备' : /Mac/.test(navigator.userAgent) ? 'Mac' : /Windows/.test(navigator.userAgent) ? 'Windows 电脑' : '通行密钥');
      await LP.postJson(button.dataset.registerUrl, { name, response: { clientDataJSON: bytesToB64u(credential.response.clientDataJSON), attestationObject: bytesToB64u(credential.response.attestationObject) } });
      location.reload();
    } catch (error) { if (!cancelled(error)) say(error.message || '通行密钥添加失败'); button.disabled = false; }
  }));

  /* recovery codes: require "saved" before continuing; offer a text download */
  const codes = document.querySelector('[data-e2fa-codes]');
  if (codes) {
    const saved = document.querySelector('[data-e2fa-saved]');
    const done = document.querySelector('[data-e2fa-done]');
    const sync = () => { if (done.tagName === 'A') done.setAttribute('aria-disabled', String(!saved.checked)); else done.disabled = !saved.checked; done.classList.toggle('is-disabled', !saved.checked); };
    saved.addEventListener('change', sync); sync();
    done.addEventListener('click', (event) => { if (!saved.checked) { event.preventDefault(); say('请先确认已保存还原码'); } });
    document.querySelector('[data-e2fa-download]')?.addEventListener('click', () => {
      const text = `${document.title}\n${location.host} 两步验证还原码（每个只能用一次）\n\n${[...codes.querySelectorAll('code')].map((c) => c.textContent).join('\n')}\n`;
      const link = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' })), download: `${location.host}-recovery-codes.txt` });
      link.click(); URL.revokeObjectURL(link.href); saved.checked = true; sync();
    });
  }
})();
