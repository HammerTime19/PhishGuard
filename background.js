// ============================================================
// PhishGuard — Background Service Worker (v2.0.3)
// Added: WHOIS domain age with monthly quota + 30-day cache
// src/background.js
// ============================================================

import { analyzeURL } from './heuristics.js';
import { PHISHGUARD_CONFIG } from './config.js';

// ── In-memory caches ──────────────────────────────────────────
const tabCache    = new Map();  // tabId  → full result
const domainCache = new Map();  // domain → { apiResults, timestamp }

// ── Rate limit config ─────────────────────────────────────────
//
//  VirusTotal   : 500 calls/day   → we cap at 450/day, 4/min
//  Safe Browsing: 10,000 calls/day → we cap at 9,000/day
//  WHOIS        : 50 calls TOTAL (trial) → we cap at 45/month, 2/min
//    ↑ WHOIS is monthly, not daily — handled separately below
//
const RATE_LIMITS = {
  virusTotal:   { dailyMax: 450,  minuteMax: 4  },
  safeBrowsing: { dailyMax: 9000, minuteMax: 60 },
};

// WHOIS has a monthly quota — stored separately
const WHOIS_MONTHLY_MAX = 45;   // hard cap (real limit is 50, buffer of 5)
const WHOIS_MINUTE_MAX  = 2;    // max 2 calls per minute to be safe

// Cache TTLs
const DOMAIN_CACHE_TTL_MS      = 6  * 60 * 60 * 1000;  // 6 hours  — for VT + SB
const WHOIS_CACHE_TTL_MS       = 30 * 24 * 60 * 60 * 1000; // 30 days — domain age barely changes

// Well-known trusted domains — skip ALL API calls for these
const TRUSTED_DOMAINS = new Set([
  'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com',
  'x.com', 'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'wikipedia.org', 'reddit.com', 'netflix.com', 'github.com', 'stackoverflow.com',
  'gmail.com', 'outlook.com', 'yahoo.com', 'bing.com', 'office.com',
  'live.com', 'icloud.com', 'dropbox.com', 'zoom.us', 'slack.com',
  'notion.so', 'figma.com', 'canva.com', 'adobe.com', 'spotify.com',
  'twitch.tv', 'discord.com', 'whatsapp.com', 'telegram.org', 'tiktok.com',
]);

// Quota state (persisted to chrome.storage)
let quotaCounters = {};
/*
  Structure:
  {
    virusTotal:   { date: 'YYYY-MM-DD', daily: 0, minute: 0, minuteStart: ts },
    safeBrowsing: { date: 'YYYY-MM-DD', daily: 0, minute: 0, minuteStart: ts },
    whois:        { month: 'YYYY-MM',   monthly: 0, minute: 0, minuteStart: ts }
  }
*/

// ── Persist quota to storage ──────────────────────────────────
async function loadQuota() {
  return new Promise(resolve => {
    chrome.storage.local.get('quotaCounters', data => {
      quotaCounters = data.quotaCounters || {};
      resolve();
    });
  });
}
async function saveQuota() {
  return new Promise(resolve => chrome.storage.local.set({ quotaCounters }, resolve));
}
loadQuota();

// ── Daily quota check (VT, SB) ────────────────────────────────
function canCallDaily(apiName) {
  const limits = RATE_LIMITS[apiName];
  if (!limits) return true;

  const today = new Date().toISOString().slice(0, 10);
  const now   = Date.now();

  if (!quotaCounters[apiName] || quotaCounters[apiName].date !== today) {
    quotaCounters[apiName] = { date: today, daily: 0, minute: 0, minuteStart: now };
  }
  const c = quotaCounters[apiName];

  // Reset per-minute window
  if (now - c.minuteStart > 60000) { c.minute = 0; c.minuteStart = now; }

  return c.daily < limits.dailyMax && c.minute < limits.minuteMax;
}

function recordDaily(apiName) {
  if (!quotaCounters[apiName]) return;
  quotaCounters[apiName].daily++;
  quotaCounters[apiName].minute++;
  saveQuota();
}

// ── Monthly quota check (WHOIS) ───────────────────────────────
function canCallWhois() {
  const thisMonth = new Date().toISOString().slice(0, 7); // 'YYYY-MM'
  const now       = Date.now();

  if (!quotaCounters.whois || quotaCounters.whois.month !== thisMonth) {
    // New month — reset counter
    quotaCounters.whois = { month: thisMonth, monthly: 0, minute: 0, minuteStart: now };
  }
  const c = quotaCounters.whois;

  // Reset per-minute window
  if (now - c.minuteStart > 60000) { c.minute = 0; c.minuteStart = now; }

  return c.monthly < WHOIS_MONTHLY_MAX && c.minute < WHOIS_MINUTE_MAX;
}

function recordWhois() {
  if (!quotaCounters.whois) return;
  quotaCounters.whois.monthly++;
  quotaCounters.whois.minute++;
  saveQuota();
}

function getRemainingWhois() {
  const thisMonth = new Date().toISOString().slice(0, 7);
  if (!quotaCounters.whois || quotaCounters.whois.month !== thisMonth) return WHOIS_MONTHLY_MAX;
  return WHOIS_MONTHLY_MAX - quotaCounters.whois.monthly;
}

function getRemainingDaily(apiName) {
  const limits = RATE_LIMITS[apiName];
  if (!limits) return null;
  const today = new Date().toISOString().slice(0, 10);
  const c = quotaCounters[apiName];
  if (!c || c.date !== today) return limits.dailyMax;
  return limits.dailyMax - c.daily;
}

// ── Domain helpers ────────────────────────────────────────────
function getDomain(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    const parts = hostname.split('.');
    return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  } catch { return null; }
}

function isTrustedDomain(url) {
  const domain = getDomain(url);
  return domain ? TRUSTED_DOMAINS.has(domain) : false;
}

// ── Tab lifecycle ─────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && !tab.url.startsWith('chrome://')) {
    analyzeTab(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab.url && !tab.url.startsWith('chrome://') && !tabCache.has(tabId)) {
      analyzeTab(tabId, tab.url);
    }
  } catch { /* tab closed */ }
});

chrome.tabs.onRemoved.addListener((tabId) => tabCache.delete(tabId));

// ── DOM result from content script ───────────────────────────
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type === 'DOM_RESULT' && sender.tab) {
    const tabId     = sender.tab.id;
    const url       = sender.tab.url;
    const domResult = { domRiskScore: msg.domRiskScore, findings: msg.findings, meta: msg.meta };
    const existing  = tabCache.get(tabId);
    if (existing) {
      const urlResult = { riskScore: existing.urlScore, findings: existing.findings.filter(f => f.source === 'url') };
      const merged = combineResults(urlResult, domResult, existing.url, existing.apiResults || {});
      tabCache.set(tabId, merged);
      updateBadge(tabId, merged.verdict);
    } else {
      analyzeTab(tabId, url);
    }
  }
});

// ── Popup message handler ─────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'GET_ANALYSIS') {
    const tabId = msg.tabId;
    if (tabCache.has(tabId) && !msg.forceRescan) {
      sendResponse({ success: true, data: tabCache.get(tabId) });
    } else {
      chrome.tabs.get(tabId, (tab) => {
        if (tab?.url) {
          analyzeTab(tabId, tab.url, true).then(() => {
            sendResponse({ success: true, data: tabCache.get(tabId) });
          });
        } else {
          sendResponse({ success: false });
        }
      });
    }
    return true;
  }

  if (msg.type === 'GET_QUOTA') {
    sendResponse({
      virusTotal:   getRemainingDaily('virusTotal'),
      safeBrowsing: getRemainingDaily('safeBrowsing'),
      whois:        getRemainingWhois(),
    });
    return true;
  }
});

// ── Core analysis orchestrator ────────────────────────────────
async function analyzeTab(tabId, url) {
  const urlResult = analyzeURL(url);

  let domResult = { domRiskScore: 0, findings: [], meta: {} };
  try {
    const res = await chrome.tabs.sendMessage(tabId, { type: 'ANALYZE_DOM' });
    if (res?.success !== false) domResult = res;
  } catch { /* content script not ready */ }

  // Fast initial result (no APIs yet)
  let combined = combineResults(urlResult, domResult, url, {});
  tabCache.set(tabId, combined);
  updateBadge(tabId, combined.verdict);

  // Full API checks with rate limiting
  const apiResults = await runAPIChecks(url);

  combined = combineResults(urlResult, domResult, url, apiResults);
  tabCache.set(tabId, combined);
  updateBadge(tabId, combined.verdict);

  return combined;
}

// ── API checks with full rate limiting + caching ──────────────
async function runAPIChecks(url) {
  const domain = getDomain(url);

  // Layer 1: skip trusted domains entirely
  if (isTrustedDomain(url)) {
    return { _skipped: true, _reason: 'trusted_domain' };
  }

  // Layer 2: check domain cache
  // WHOIS cache is stored separately (30 days) vs other APIs (6 hours)
  const now = Date.now();
  let cachedWhois    = null;
  let cachedNonWhois = null;

  if (domain) {
    const cached = domainCache.get(domain);
    if (cached) {
      // Check non-WHOIS cache (6 hours)
      if (now - cached.timestamp < DOMAIN_CACHE_TTL_MS) {
        cachedNonWhois = { safeBrowsing: cached.safeBrowsing, virusTotal: cached.virusTotal };
      }
      // Check WHOIS cache (30 days)
      if (cached.whoisTimestamp && now - cached.whoisTimestamp < WHOIS_CACHE_TTL_MS) {
        cachedWhois = cached.whois;
      }
    }
  }

  const results = {};
  const checks  = [];

  // ── Google Safe Browsing ──
  if (cachedNonWhois?.safeBrowsing) {
    results.safeBrowsing = { ...cachedNonWhois.safeBrowsing, _fromCache: true };
  } else if (PHISHGUARD_CONFIG.SAFE_BROWSING_KEY && !PHISHGUARD_CONFIG.SAFE_BROWSING_KEY.startsWith('YOUR_')) {
    if (canCallDaily('safeBrowsing')) {
      checks.push(
        checkGoogleSafeBrowsing(url, PHISHGUARD_CONFIG.SAFE_BROWSING_KEY)
          .then(r  => { results.safeBrowsing = r; recordDaily('safeBrowsing'); })
          .catch(e => { results.safeBrowsing = { error: e.message, checked: false }; })
      );
    } else {
      results.safeBrowsing = { checked: false, rateLimited: true };
    }
  }

  // ── VirusTotal ──
  if (cachedNonWhois?.virusTotal) {
    results.virusTotal = { ...cachedNonWhois.virusTotal, _fromCache: true };
  } else if (PHISHGUARD_CONFIG.VIRUSTOTAL_KEY && !PHISHGUARD_CONFIG.VIRUSTOTAL_KEY.startsWith('YOUR_')) {
    if (canCallDaily('virusTotal')) {
      checks.push(
        checkVirusTotal(url, PHISHGUARD_CONFIG.VIRUSTOTAL_KEY)
          .then(r  => { results.virusTotal = r; recordDaily('virusTotal'); })
          .catch(e => { results.virusTotal = { error: e.message, checked: false }; })
      );
    } else {
      results.virusTotal = { checked: false, rateLimited: true };
    }
  }

  // ── WHOIS (monthly quota + 30-day cache) ──
  if (cachedWhois) {
    results.whois = { ...cachedWhois, _fromCache: true };
  } else if (PHISHGUARD_CONFIG.WHOIS_KEY && !PHISHGUARD_CONFIG.WHOIS_KEY.startsWith('YOUR_')) {
    if (canCallWhois()) {
      checks.push(
        checkDomainAge(url, PHISHGUARD_CONFIG.WHOIS_KEY)
          .then(r  => { results.whois = r; recordWhois(); })
          .catch(e => { results.whois = { error: e.message, checked: false }; })
      );
    } else {
      results.whois = {
        checked: false,
        rateLimited: true,
        remaining: getRemainingWhois()
      };
    }
  }

  await Promise.allSettled(checks);

  // Layer 4: update domain cache with split TTLs
  if (domain) {
    const existing = domainCache.get(domain) || {};
    domainCache.set(domain, {
      ...existing,
      safeBrowsing:   results.safeBrowsing,
      virusTotal:     results.virusTotal,
      timestamp:      now,
      // WHOIS only updated if we actually made a fresh call
      whois:          results.whois?.checked ? results.whois : existing.whois,
      whoisTimestamp: results.whois?.checked ? now           : existing.whoisTimestamp,
    });
  }

  return results;
}

// ── Google Safe Browsing ──────────────────────────────────────
async function checkGoogleSafeBrowsing(url, apiKey) {
  const res = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'phishguard', clientVersion: '2.0.3' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      })
    }
  );
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data    = await res.json();
  const matches = data.matches || [];
  return { checked: true, isBlacklisted: matches.length > 0, threatTypes: matches.map(m => m.threatType) };
}

// ── VirusTotal ────────────────────────────────────────────────
async function checkVirusTotal(url, apiKey) {
  await fetch('https://www.virustotal.com/api/v3/urls', {
    method: 'POST',
    headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `url=${encodeURIComponent(url)}`
  });

  const urlId  = btoa(url).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const res    = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, { headers: { 'x-apikey': apiKey } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const data   = await res.json();
  const stats  = data.data?.attributes?.last_analysis_stats || {};
  const malicious  = stats.malicious  || 0;
  const suspicious = stats.suspicious || 0;
  const harmless   = stats.harmless   || 0;
  const undetected = stats.undetected || 0;
  const total = malicious + suspicious + harmless + undetected;

  return { checked: true, malicious, suspicious, harmless, undetected, total, positiveEngines: malicious + suspicious };
}

// ── WHOIS Domain Age ──────────────────────────────────────────
async function checkDomainAge(url, apiKey) {
  const hostname = new URL(url).hostname.replace(/^www\./, '');

  const res = await fetch(
    `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${hostname}&outputFormat=JSON`
  );
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const data           = await res.json();
  const record         = data.WhoisRecord || {};
  const createdDateStr = record.createdDate || record.registryData?.createdDate;

  if (!createdDateStr) {
    return { checked: true, ageInDays: null, domain: hostname, registrar: record.registrarName || null };
  }

  const ageInDays = Math.floor((Date.now() - new Date(createdDateStr).getTime()) / 86400000);

  return {
    checked:     true,
    ageInDays,
    createdDate: createdDateStr,
    domain:      hostname,
    registrar:   record.registrarName || null,
    expiresDate: record.expiresDate   || null,
  };
}

// ── Combine all results into final verdict ────────────────────
function combineResults(urlResult, domResult, url, apiResults = {}) {
  const findings = [];
  (urlResult.findings || []).forEach(f => findings.push({ ...f, source: 'url' }));
  (domResult.findings || []).forEach(f => findings.push({ ...f, source: 'dom' }));

  // Skip / cache notes
  if (apiResults._skipped) {
    findings.push({ source: 'api', severity: 'low', msg: 'Trusted domain — API scan skipped \u2713' });
  }

  // ── Safe Browsing ──
  let safeBrowsingScore = 0;
  const sb = apiResults.safeBrowsing;
  if (sb?.rateLimited) {
    findings.push({ source: 'api', severity: 'low', msg: `Google Safe Browsing: daily quota reached — skipped` });
  } else if (sb?.checked && sb.isBlacklisted) {
    safeBrowsingScore = 100;
    findings.push({ source: 'api', severity: 'high', msg: `Google Safe Browsing: BLACKLISTED — ${sb.threatTypes.join(', ') || 'threat detected'}` });
  } else if (sb?.checked) {
    const cacheNote = sb._fromCache ? ' (cached)' : '';
    findings.push({ source: 'api', severity: 'low', msg: `Google Safe Browsing: Not in threat database \u2713${cacheNote}` });
  } else if (sb?.error) {
    findings.push({ source: 'api', severity: 'low', msg: `Google Safe Browsing error: ${sb.error}` });
  }

  // ── VirusTotal ──
  let vtScore = 0;
  const vt = apiResults.virusTotal;
  if (vt?.rateLimited) {
    findings.push({ source: 'api', severity: 'low', msg: `VirusTotal: daily quota reached (${getRemainingDaily('virusTotal')} left today) — skipped` });
  } else if (vt?.checked) {
    vtScore = vt.total > 0 ? Math.round((vt.positiveEngines / vt.total) * 100) : 0;
    const cacheNote = vt._fromCache ? ' (cached)' : '';
    if (vt.malicious >= 3) {
      findings.push({ source: 'api', severity: 'high',   msg: `VirusTotal: ${vt.malicious} engines flagged MALICIOUS out of ${vt.total}${cacheNote}` });
    } else if (vt.positiveEngines > 0) {
      findings.push({ source: 'api', severity: 'medium', msg: `VirusTotal: ${vt.positiveEngines} engine(s) flagged out of ${vt.total}${cacheNote}` });
    } else {
      findings.push({ source: 'api', severity: 'low',    msg: `VirusTotal: Clean across all ${vt.total} engines \u2713${cacheNote}` });
    }
  } else if (vt?.error) {
    findings.push({ source: 'api', severity: 'low', msg: `VirusTotal error: ${vt.error}` });
  }

  // ── WHOIS Domain Age ──
  let whoisScore = 0;
  const whois = apiResults.whois;
  if (whois?.rateLimited) {
    findings.push({ source: 'api', severity: 'low', msg: `WHOIS: monthly quota reached (${whois.remaining ?? 0} of ${WHOIS_MONTHLY_MAX} calls left this month) — skipped` });
  } else if (whois?.checked && whois.ageInDays !== null) {
    const cacheNote = whois._fromCache ? ' (cached)' : '';
    if (whois.ageInDays < 7) {
      whoisScore = 60;
      findings.push({ source: 'api', severity: 'high',   msg: `Domain registered only ${whois.ageInDays} day(s) ago — extremely suspicious${cacheNote}` });
    } else if (whois.ageInDays < 30) {
      whoisScore = 45;
      findings.push({ source: 'api', severity: 'high',   msg: `Domain is ${whois.ageInDays} days old — newly registered (high risk)${cacheNote}` });
    } else if (whois.ageInDays < 90) {
      whoisScore = 20;
      findings.push({ source: 'api', severity: 'medium', msg: `Domain is ${whois.ageInDays} days old — relatively new (< 90 days)${cacheNote}` });
    } else {
      const yrs = Math.floor(whois.ageInDays / 365);
      const mos = Math.floor((whois.ageInDays % 365) / 30);
      findings.push({ source: 'api', severity: 'low', msg: `Domain age: ${yrs}y ${mos}m — well established \u2713${cacheNote}` });
    }
    if (whois.registrar && !whois._fromCache) {
      findings.push({ source: 'api', severity: 'low', msg: `Registrar: ${whois.registrar}` });
    }
  } else if (whois?.checked && whois.ageInDays === null) {
    findings.push({ source: 'api', severity: 'medium', msg: 'WHOIS: domain registration date unavailable — treat with caution' });
  } else if (whois?.error) {
    findings.push({ source: 'api', severity: 'low', msg: `WHOIS error: ${whois.error}` });
  }

  // ── Final score ──
  const apiOverride = sb?.checked && sb.isBlacklisted;
  let combinedScore;

  if (apiOverride) {
    combinedScore = 100;
  } else {
    const hasAPIs = sb?.checked || vt?.checked || whois?.checked;
    if (hasAPIs) {
      const apiScore = Math.min(Math.max(safeBrowsingScore, vtScore, whoisScore), 100);
      combinedScore = Math.round(
        (urlResult.riskScore * 0.20) +
        ((domResult.domRiskScore || 0) * 0.30) +
        (apiScore * 0.50)
      );
    } else {
      combinedScore = Math.round(
        (urlResult.riskScore * 0.40) +
        ((domResult.domRiskScore || 0) * 0.60)
      );
    }
  }
  combinedScore = Math.min(combinedScore, 100);

  let verdict, confidence;
  if (combinedScore >= 60 || apiOverride) {
    verdict = 'PHISHING'; confidence = (combinedScore >= 80 || apiOverride) ? 'HIGH' : 'MEDIUM';
  } else if (combinedScore >= 30) {
    verdict = 'SUSPICIOUS'; confidence = 'MEDIUM';
  } else {
    verdict = 'SAFE'; confidence = combinedScore <= 10 ? 'HIGH' : 'MEDIUM';
  }

  return {
    url, verdict, confidence, combinedScore,
    urlScore:   urlResult.riskScore,
    domScore:   domResult.domRiskScore || 0,
    apiScores:  { safeBrowsing: safeBrowsingScore, virusTotal: vtScore, whois: whoisScore },
    apiResults,
    findings,
    meta:       domResult.meta || {},
    timestamp:  Date.now()
  };
}

// ── Badge ─────────────────────────────────────────────────────
function updateBadge(tabId, verdict) {
  const cfg = {
    PHISHING:   { text: '!', color: '#FF2D55' },
    SUSPICIOUS: { text: '?', color: '#FF9F0A' },
    SAFE:       { text: '\u2713', color: '#30D158' }
  };
  const { text, color } = cfg[verdict] || { text: '', color: '#888' };
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}
