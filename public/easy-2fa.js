/*
 * Easy 2FA Front-End Script
 *
 * Progressive-enhancement script for the challenge and security pages.
 *
 * Authors:
 * MoyuZJ <moyuzj@moyuzj.cn> @LinearTeam - Made in China with ♥
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Two-step verification - front-end script.
 *  1. Challenge page: switching between the TOTP / recovery-code forms + WebAuthn passkey
 *     login (does not consume recovery codes).
 *  2. Account security page: adding passkeys (navigator.credentials.create).
 * Everything is progressive enhancement: when scripts are unavailable, the TOTP and
 * recovery-code flows are unaffected.
 *
 * @since 1.0.0
 */

(() => {
  'use strict';

  /* ---------------- Base64URL 工具（BufferSource ↔ 字符串） ---------------- */
  function b64uToBytes(value) {
    const buffer = atob(value.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''));
    return Uint8Array.from(buffer, (c) => c.charCodeAt(0));
  }
  function bytesToB64u(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function postJson(url, payload) {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(payload || {})
    });
    return { ok: response.ok, data: await response.json().catch(() => ({})) };
  }

  function showError(message) {
    let box = document.querySelector('.e2fa-error[data-dynamic]');
    if (!box) {
      box = document.createElement('p');
      box.className = 'e2fa-error';
      box.setAttribute('data-dynamic', '');
      const page = document.querySelector('.e2fa-page');
      if (page && page.parentNode) page.parentNode.insertBefore(box, page);
      else document.body.prepend(box);
    }
    box.textContent = message;
  }

  /* ---------------- 挑战页：方式切换 ---------------- */
  function initTabs() {
    const tabs = Array.from(document.querySelectorAll('.e2fa-method-tab'));
    if (!tabs.length) return;
    const panels = Array.from(document.querySelectorAll('.e2fa-method-panel'));
    const activate = (name) => {
      tabs.forEach((tab) => tab.setAttribute('data-active', String(tab.dataset.method === name)));
      panels.forEach((panel) => panel.setAttribute('data-active', String(panel.dataset.method === name)));
    };
    tabs.forEach((tab) => tab.addEventListener('click', () => activate(tab.dataset.method)));
    activate(tabs.some((t) => t.dataset.method === 'totp') ? 'totp' : (tabs[0]?.dataset.method || 'totp'));
  }

  /* ---------------- WebAuthn：通行密钥登录 ---------------- */
  async function loginWithPasskey(button) {
    const url = button.dataset.optionsUrl;
    try {
      button.disabled = true;
      const optionsResponse = await fetch(url, { headers: { accept: 'application/json' } });
      if (!optionsResponse.ok) throw new Error((await optionsResponse.json().catch(() => ({}))).message || '无法获取挑战。');
      const options = await optionsResponse.json();

      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: b64uToBytes(options.challenge),
          rpId: options.rpId,
          timeout: options.timeout || 60000,
          userVerification: options.userVerification || 'preferred',
          allowCredentials: (options.allowCredentials || []).map((d) => ({ id: b64uToBytes(d.id), type: d.type, transports: d.transports }))
        }
      });
      if (!credential) throw new Error('未获取到通行密钥。');

      const assertion = await postJson(button.dataset.verifyUrl, {
        id: credential.id,
        rawId: bytesToB64u(credential.rawId),
        response: {
          clientDataJSON: bytesToB64u(credential.response.clientDataJSON),
          authenticatorData: bytesToB64u(credential.response.authenticatorData),
          signature: bytesToB64u(credential.response.signature),
          userHandle: credential.response.userHandle ? bytesToB64u(credential.response.userHandle) : null
        }
      });
      if (!assertion.ok || !assertion.data.ok) throw new Error(assertion.data.message || '通行密钥验证失败。');
      window.location.assign(assertion.data.redirect || '/admin');
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'NotAllowedError')) showError(error.message || '通行密钥验证失败。');
      button.disabled = false;
    }
  }

  /* ---------------- 账户安全页：注册新通行密钥 ---------------- */
  async function registerPasskey(button) {
    try {
      button.disabled = true;
      const optionsResponse = await fetch(button.dataset.optionsUrl, { headers: { accept: 'application/json' } });
      if (!optionsResponse.ok) throw new Error((await optionsResponse.json().catch(() => ({}))).message || '无法获取注册挑战。');
      const options = await optionsResponse.json();

      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: b64uToBytes(options.challenge),
          rp: options.rp,
          user: { ...options.user, id: b64uToBytes(options.user.id) },
          pubKeyCredParams: options.pubKeyCredParams,
          timeout: options.timeout || 60000,
          attestation: options.attestation || 'none',
          excludeCredentials: (options.excludeCredentials || []).map((d) => ({ id: b64uToBytes(d.id), type: d.type })),
          authenticatorSelection: options.authenticatorSelection
        }
      });
      if (!credential) throw new Error('未创建任何凭证。');

      const result = await postJson(button.dataset.registerUrl, {
        id: credential.id,
        rawId: bytesToB64u(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bytesToB64u(credential.response.clientDataJSON),
          attestationObject: bytesToB64u(credential.response.attestationObject)
        },
        name: window.prompt('为这把通行密钥起个名字（如「我的手机」）：', '') || ''
      });
      if (!result.ok || !result.data.ok) throw new Error(result.data.message || '通行密钥注册失败。');
      window.location.reload();
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'NotAllowedError')) showError(error.message || '通行密钥注册失败。');
      button.disabled = false;
    }
  }

  /* ---------------- 初始化 ---------------- */
  document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    document.querySelectorAll('[data-e2fa-confirm]').forEach((button) =>
      button.addEventListener('click', (event) => {
        if (!window.confirm(button.dataset.e2faConfirm)) event.preventDefault();
      }));
    document.querySelectorAll('[data-e2fa-passkey-login]').forEach((button) =>
      button.addEventListener('click', (event) => { event.preventDefault(); void loginWithPasskey(button); }));
    document.querySelectorAll('[data-e2fa-passkey-register]').forEach((button) =>
      button.addEventListener('click', (event) => { event.preventDefault(); void registerPasskey(button); }));
  });
})();
