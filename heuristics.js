// ============================================================
// PhishGuard — URL Heuristics Engine
// src/heuristics.js
// ============================================================

const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.top', '.club', '.work', '.party', '.gq', '.ml', '.cf', '.tk',
  '.pw', '.cc', '.su', '.biz', '.info', '.link', '.click', '.live', '.online'
]);

const LEGIT_BRANDS = [
  'paypal', 'google', 'facebook', 'apple', 'amazon', 'microsoft', 'netflix',
  'instagram', 'twitter', 'linkedin', 'chase', 'bankofamerica', 'wellsfargo',
  'citibank', 'ebay', 'dropbox', 'icloud', 'outlook', 'office365', 'gmail'
];

// Common homoglyph / typosquat patterns
const HOMOGLYPHS = {
  'a': ['@', '4', 'á', 'à', 'ä'],
  'e': ['3', 'é', 'è'],
  'i': ['1', 'l', '!', 'í'],
  'o': ['0', 'ó', 'ò'],
  's': ['5', '$'],
  'g': ['9'],
  'l': ['1', 'I']
};

function analyzeURL(urlString) {
  const findings = [];
  let riskScore = 0;

  let url;
  try {
    url = new URL(urlString);
  } catch {
    return { riskScore: 100, findings: [{ type: 'error', msg: 'Invalid URL', severity: 'high' }] };
  }

  const hostname = url.hostname.toLowerCase();
  const fullURL = urlString.toLowerCase();

  // ── 1. IP Address as hostname ──────────────────────────────
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipPattern.test(hostname)) {
    riskScore += 40;
    findings.push({ type: 'url', severity: 'high', msg: 'Site uses a raw IP address instead of a domain name' });
  }

  // ── 2. Suspicious TLD ─────────────────────────────────────
  const tld = '.' + hostname.split('.').pop();
  if (SUSPICIOUS_TLDS.has(tld)) {
    riskScore += 20;
    findings.push({ type: 'url', severity: 'medium', msg: `Suspicious top-level domain: "${tld}"` });
  }

  // ── 3. Excessive subdomains ───────────────────────────────
  const parts = hostname.split('.');
  if (parts.length > 4) {
    riskScore += 15;
    findings.push({ type: 'url', severity: 'medium', msg: `Unusually deep subdomain chain (${parts.length} levels)` });
  }

  // ── 4. Brand name in subdomain (not the actual domain) ────
  const registrableDomain = parts.slice(-2).join('.');
  for (const brand of LEGIT_BRANDS) {
    if (hostname.includes(brand) && !registrableDomain.includes(brand)) {
      riskScore += 35;
      findings.push({
        type: 'url', severity: 'high',
        msg: `Brand name "${brand}" appears in subdomain but not the real domain — likely spoofing`
      });
      break;
    }
  }

  // ── 5. Homoglyph / typosquat detection ───────────────────
  for (const brand of LEGIT_BRANDS) {
    if (hostname !== brand + '.com' && isSimilar(hostname.replace(/\./g, ''), brand)) {
      riskScore += 30;
      findings.push({
        type: 'url', severity: 'high',
        msg: `Domain looks like a typosquat or lookalike of "${brand}"`
      });
      break;
    }
  }

  // ── 6. Excessive hyphens ──────────────────────────────────
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    riskScore += 10;
    findings.push({ type: 'url', severity: 'low', msg: `Domain has ${hyphenCount} hyphens — common in phishing domains` });
  }

  // ── 7. Numeric tokens in domain ──────────────────────────
  if (/\d{4,}/.test(hostname)) {
    riskScore += 10;
    findings.push({ type: 'url', severity: 'low', msg: 'Long numeric sequence in domain name' });
  }

  // ── 8. Suspicious keywords in URL ─────────────────────────
  const suspiciousKeywords = [
    'secure', 'login', 'verify', 'update', 'confirm', 'account', 'banking',
    'signin', 'ebayisapi', 'webscr', 'cmd=_login', 'password', 'credential'
  ];
  const matchedKeywords = suspiciousKeywords.filter(k => fullURL.includes(k));
  if (matchedKeywords.length >= 2) {
    riskScore += 15;
    findings.push({
      type: 'url', severity: 'medium',
      msg: `Multiple sensitive keywords in URL: ${matchedKeywords.slice(0, 3).join(', ')}`
    });
  }

  // ── 9. Non-HTTPS ─────────────────────────────────────────
  if (url.protocol !== 'https:') {
    riskScore += 20;
    findings.push({ type: 'url', severity: 'high', msg: 'Connection is NOT encrypted (HTTP, not HTTPS)' });
  }

  // ── 10. Excessively long URL ──────────────────────────────
  if (urlString.length > 200) {
    riskScore += 10;
    findings.push({ type: 'url', severity: 'low', msg: `URL is unusually long (${urlString.length} characters)` });
  }

  // ── 11. URL shortener detection ───────────────────────────
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly'];
  if (shorteners.some(s => hostname.includes(s))) {
    riskScore += 15;
    findings.push({ type: 'url', severity: 'medium', msg: 'URL appears to be a shortened link — true destination is hidden' });
  }

  // ── 12. Data URI / encoded tricks ────────────────────────
  if (fullURL.includes('%00') || fullURL.includes('data:text') || fullURL.includes('javascript:')) {
    riskScore += 50;
    findings.push({ type: 'url', severity: 'high', msg: 'URL contains obfuscation techniques (null bytes, data URIs, or JS protocol)' });
  }

  return {
    riskScore: Math.min(riskScore, 100),
    findings,
    hostname,
    registrableDomain
  };
}

// Levenshtein-based similarity for typosquat detection
function isSimilar(str, target) {
  if (Math.abs(str.length - target.length) > 2) return false;
  const dist = levenshtein(str, target);
  return dist > 0 && dist <= 2;
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

// Export for use in background.js and popup
if (typeof module !== 'undefined') module.exports = { analyzeURL };

export { analyzeURL };
