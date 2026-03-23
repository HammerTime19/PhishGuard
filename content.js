// ============================================================
// PhishGuard — Content Script
// Runs INSIDE every webpage (bypasses CORS restrictions!)
// src/content.js
// ============================================================

(function () {
  'use strict';

  function analyzeDOMForPhishing() {
    const findings = [];
    let domRiskScore = 0;

    const currentHost = window.location.hostname.toLowerCase();

    // ── 1. Password field present ─────────────────────────────
    const passwordFields = document.querySelectorAll('input[type="password"]');
    const hasPasswordField = passwordFields.length > 0;

    // ── 2. Login/credential form detection ───────────────────
    const loginKeywords = ['login', 'signin', 'log-in', 'sign-in', 'username', 'email', 'user', 'account'];
    const forms = Array.from(document.querySelectorAll('form'));
    let hasSuspiciousForm = false;

    for (const form of forms) {
      const formText = form.innerText?.toLowerCase() + form.innerHTML?.toLowerCase();
      const matchCount = loginKeywords.filter(k => formText.includes(k)).length;
      if (matchCount >= 2 && hasPasswordField) {
        hasSuspiciousForm = true;
        break;
      }
    }

    // ── 3. Form action points to different domain ─────────────
    for (const form of forms) {
      const action = form.getAttribute('action') || '';
      if (action.startsWith('http') || action.startsWith('//')) {
        try {
          const actionHost = new URL(action, window.location.href).hostname.toLowerCase();
          if (actionHost && actionHost !== currentHost && !actionHost.endsWith('.' + currentHost)) {
            domRiskScore += 40;
            findings.push({
              type: 'dom', severity: 'high',
              msg: `Form submits credentials to a DIFFERENT domain: ${actionHost}`
            });
          }
        } catch { /* ignore malformed action */ }
      }
    }

    // ── 4. Hidden iframes (common in clickjacking/phishing) ──
    const hiddenIframes = Array.from(document.querySelectorAll('iframe')).filter(f => {
      const s = window.getComputedStyle(f);
      return s.display === 'none' || s.visibility === 'hidden' || f.getAttribute('width') === '0';
    });
    if (hiddenIframes.length > 0) {
      domRiskScore += 20;
      findings.push({
        type: 'dom', severity: 'medium',
        msg: `${hiddenIframes.length} hidden iframe(s) detected — possible clickjacking technique`
      });
    }

    // ── 5. Disabled right-click (anti-inspection) ─────────────
    const htmlContent = document.documentElement.innerHTML;
    if (htmlContent.includes('contextmenu') && htmlContent.includes('return false')) {
      domRiskScore += 10;
      findings.push({ type: 'dom', severity: 'low', msg: 'Right-click is disabled — site may be trying to prevent inspection' });
    }

    // ── 6. Urgency/fear language ──────────────────────────────
    const bodyText = document.body?.innerText?.toLowerCase() || '';
    const urgencyPhrases = [
      'your account has been suspended', 'verify immediately', 'unusual activity',
      'click here to avoid', 'account will be closed', 'confirm your identity',
      'limited time', 'act now', 'your account is at risk', 'unauthorized access'
    ];
    const foundUrgency = urgencyPhrases.filter(p => bodyText.includes(p));
    if (foundUrgency.length >= 2) {
      domRiskScore += 20;
      findings.push({
        type: 'dom', severity: 'medium',
        msg: `Urgency/fear language detected: "${foundUrgency[0]}"${foundUrgency.length > 1 ? ` (+${foundUrgency.length - 1} more)` : ''}`
      });
    }

    // ── 7. Favicon from a different domain ───────────────────
    const faviconLinks = Array.from(document.querySelectorAll('link[rel*="icon"]'));
    for (const link of faviconLinks) {
      const href = link.getAttribute('href') || '';
      if (href.startsWith('http')) {
        try {
          const faviconHost = new URL(href).hostname.toLowerCase();
          if (faviconHost !== currentHost) {
            domRiskScore += 15;
            findings.push({
              type: 'dom', severity: 'medium',
              msg: `Favicon loaded from external domain: ${faviconHost}`
            });
          }
        } catch { /* ignore */ }
      }
    }

    // ── 8. Excessive external script sources ─────────────────
    const scripts = Array.from(document.querySelectorAll('script[src]'));
    const externalScripts = scripts.filter(s => {
      try {
        const scriptHost = new URL(s.src, window.location.href).hostname;
        return scriptHost !== currentHost;
      } catch { return false; }
    });
    const uniqueScriptDomains = new Set(externalScripts.map(s => {
      try { return new URL(s.src).hostname; } catch { return ''; }
    }));
    if (uniqueScriptDomains.size > 8) {
      domRiskScore += 10;
      findings.push({
        type: 'dom', severity: 'low',
        msg: `Scripts loaded from ${uniqueScriptDomains.size} external domains — unusual`
      });
    }

    // ── 9. Page title vs domain mismatch ─────────────────────
    const title = document.title.toLowerCase();
    const LEGIT_BRANDS_DOM = ['paypal', 'google', 'facebook', 'apple', 'amazon', 'microsoft', 'netflix', 'chase', 'ebay'];
    for (const brand of LEGIT_BRANDS_DOM) {
      if (title.includes(brand) && !currentHost.includes(brand)) {
        domRiskScore += 30;
        findings.push({
          type: 'dom', severity: 'high',
          msg: `Page title claims to be "${brand}" but domain doesn't match`
        });
        break;
      }
    }

    // ── 10. Credential form with no HTTPS ────────────────────
    if (hasPasswordField && window.location.protocol !== 'https:') {
      domRiskScore += 35;
      findings.push({
        type: 'dom', severity: 'high',
        msg: 'Password field present on an unencrypted HTTP page'
      });
    }

    return {
      domRiskScore: Math.min(domRiskScore, 100),
      findings,
      meta: {
        hasPasswordField,
        hasSuspiciousForm,
        formCount: forms.length,
        scriptCount: scripts.length,
        title: document.title,
        url: window.location.href
      }
    };
  }

  // Listen for analysis request from background/popup
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'ANALYZE_DOM') {
      try {
        const result = analyzeDOMForPhishing();
        sendResponse({ success: true, ...result });
      } catch (err) {
        sendResponse({ success: false, error: err.message, domRiskScore: 0, findings: [] });
      }
    }
    return true; // keep channel open for async
  });

  // Auto-run and store result
  try {
    const result = analyzeDOMForPhishing();
    chrome.runtime.sendMessage({ type: 'DOM_RESULT', tabId: null, ...result });
  } catch { /* background may not be ready yet on first load */ }
})();
