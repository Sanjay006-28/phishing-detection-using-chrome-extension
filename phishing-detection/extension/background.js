const API_ROOT = "http://127.0.0.1:8000";
const API_URL = `${API_ROOT}/predict/url`;
const API_EMAIL = `${API_ROOT}/predict/email`;
const API_HEALTH = `${API_ROOT}/`;
const API_TIMEOUT_MS = 8000;
const DETECTION_THRESHOLD_KEY = "detectionThreshold";
const SCAN_HISTORY_KEY = "scanHistory";
const BACKEND_STATUS_KEY = "backendStatus";
const DEFAULT_THRESHOLD = 0.5;

let detectionThreshold = DEFAULT_THRESHOLD;
let backendOnline = false;
const lastWebsiteNotifiedByTab = new Map();

function fireAndForget(promise) {
  Promise.resolve(promise).catch(() => {});
}

function getHostname(url) {
  try {
    const withProto = /^https?:\/\//i.test(url) ? url : `http://${url}`;
    return new URL(withProto).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function clampThreshold(v) {
  const x = Number(v);
  if (!Number.isFinite(x)) return DEFAULT_THRESHOLD;
  return Math.min(0.9, Math.max(0.1, x));
}

async function loadThreshold() {
  try {
    const r = await chrome.storage.local.get({ [DETECTION_THRESHOLD_KEY]: DEFAULT_THRESHOLD });
    detectionThreshold = clampThreshold(r[DETECTION_THRESHOLD_KEY]);
    await chrome.storage.local.set({ [DETECTION_THRESHOLD_KEY]: detectionThreshold });
  } catch {
    detectionThreshold = DEFAULT_THRESHOLD;
  }
}

async function setBackendOnline(value) {
  backendOnline = Boolean(value);
  try {
    await chrome.storage.local.set({ [BACKEND_STATUS_KEY]: backendOnline });
  } catch {
    // Ignore transient service-worker/storage availability issues.
  }
}

async function checkBackendHealth() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    const res = await fetch(API_HEALTH, { method: "GET", cache: "no-store", signal: controller.signal });
    await setBackendOnline(res.ok);
    return { online: res.ok };
  } catch {
    await setBackendOnline(false);
    return { online: false };
  } finally {
    clearTimeout(timer);
  }
}

async function postJsonWithTimeout(url, payload) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

async function addHistory(entry) {
  const r = await chrome.storage.local.get({ [SCAN_HISTORY_KEY]: [] });
  const list = Array.isArray(r[SCAN_HISTORY_KEY]) ? r[SCAN_HISTORY_KEY] : [];
  list.unshift(entry);
  await chrome.storage.local.set({ [SCAN_HISTORY_KEY]: list.slice(0, 10) });
}

function toSnippet(input, max = 120) {
  const s = String(input || "").replace(/\s+/g, " ").trim();
  return s.length > max ? `${s.slice(0, max)}...` : s;
}

function explainUrl(url, result, trusted = false) {
  const u = String(url || "");
  const lower = u.toLowerCase();
  const reasons = [];
  const specials = (u.match(/[^a-zA-Z0-9]/g) || []).length;
  const specialRatio = u.length ? (specials / u.length) : 0;
  const redirects = Math.max((u.match(/https?:\/\//g) || []).length - 1, 0);
  const digitCount = (u.match(/\d/g) || []).length;
  const digitRatio = u.length ? (digitCount / u.length) : 0;
  const host = getHostname(u);
  const subdomains = host ? Math.max(host.split(".").length - 2, 0) : 0;
  const riskyKeywordMatches = (lower.match(/login|verify|secure|update|account|password|bank|wallet|confirm/g) || []).length;

  if (trusted) reasons.push("Trusted-domain allowlist match (subdomain/domain rule).");
  if (/[@]|%[0-9a-f]{2}/i.test(u)) reasons.push("Obfuscation detected: '@' or URL-encoded pattern found.");
  if (redirects > 0) reasons.push(`Redirect-like chaining detected (${redirects} extra http/https token${redirects > 1 ? "s" : ""}).`);
  if (u.length > 75) reasons.push(`Long URL length (${u.length} chars) increases phishing risk.`);
  if (specialRatio > 0.28) reasons.push(`High special-character ratio (${(specialRatio * 100).toFixed(1)}%).`);
  if (digitRatio > 0.2) reasons.push(`High digit ratio (${(digitRatio * 100).toFixed(1)}%) in URL.`);
  if (subdomains >= 3) reasons.push(`Deep subdomain chain detected (${subdomains} subdomains).`);
  if (riskyKeywordMatches > 0) reasons.push(`Risky keyword matches in URL: ${riskyKeywordMatches}.`);
  if (result.prediction === "safe" && reasons.length === 0) {
    reasons.push("No high-risk lexical or structural URL signals detected.");
  }
  return reasons.slice(0, 4);
}

function explainEmail(text, result) {
  const t = String(text || "");
  const lower = t.toLowerCase();
  const reasons = [];
  const linkCount = (t.match(/https?:\/\//gi) || []).length + (t.match(/www\./gi) || []).length;
  const urgentCount = (lower.match(/urgent|immediately|asap|verify|suspend|suspended|password|login|security alert/g) || []).length;
  const financeCount = (lower.match(/bank|paypal|account|wallet|crypto|btc|eth/g) || []).length;
  const sensitiveCount = (lower.match(/otp|pin|cvv|ssn|social security|credit card/g) || []).length;
  const exclamations = (t.match(/!/g) || []).length;

  if (urgentCount > 0) reasons.push(`Urgency/security trigger words found (${urgentCount}).`);
  if (financeCount > 0) reasons.push(`Financial-target keywords found (${financeCount}).`);
  if (linkCount > 0) reasons.push(`Clickable link indicators found (${linkCount}).`);
  if (sensitiveCount > 0) reasons.push(`Sensitive-data request terms found (${sensitiveCount}).`);
  if (exclamations >= 3) reasons.push(`High punctuation urgency pattern (${exclamations} exclamation marks).`);
  if (result.prediction === "safe" && reasons.length === 0) {
    reasons.push("No strong social-engineering or credential-theft signals detected.");
  }
  return reasons.slice(0, 4);
}

function withThreshold(baseResult) {
  const raw = Number(baseResult?.rawScore ?? 0);
  const score = Math.min(1, Math.max(0, raw));
  const prediction = score >= detectionThreshold ? "phishing" : "safe";
  const confidence = prediction === "phishing" ? score : 1 - score;
  return {
    prediction,
    confidence: Number(confidence.toFixed(4)),
    rawScore: Number(score.toFixed(4))
  };
}

fireAndForget(loadThreshold());
fireAndForget(checkBackendHealth());

chrome.runtime.onInstalled.addListener(() => {
  fireAndForget(checkBackendHealth());
  fireAndForget(loadThreshold());
});

chrome.runtime.onStartup.addListener(() => {
  fireAndForget(checkBackendHealth());
  fireAndForget(loadThreshold());
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes[DETECTION_THRESHOLD_KEY]) {
    detectionThreshold = clampThreshold(changes[DETECTION_THRESHOLD_KEY].newValue);
  }
});

function normalizeResult(raw) {
  const rawScoreFromApi = Number(raw?.raw_score);
  const apiPrediction = String(raw?.prediction || "unknown").toLowerCase();
  const apiConfidence = Number(raw?.confidence || 0);
  const derivedScore = apiPrediction === "phishing" ? apiConfidence : 1 - apiConfidence;
  const rawScore = Number.isFinite(rawScoreFromApi) ? rawScoreFromApi : derivedScore;
  return {
    prediction: apiPrediction,
    confidence: Number(apiConfidence || 0),
    rawScore: Math.min(1, Math.max(0, rawScore)),
    modelRawScore: Number.isFinite(Number(raw?.model_raw_score)) ? Math.min(1, Math.max(0, Number(raw.model_raw_score))) : null,
    heuristicScore: Number.isFinite(Number(raw?.heuristic_score)) ? Math.min(1, Math.max(0, Number(raw.heuristic_score))) : null,
    benignDiscount: Number.isFinite(Number(raw?.benign_discount)) ? Math.min(1, Math.max(0, Number(raw.benign_discount))) : null
  };
}

async function detectUrl(url) {
  const res = await postJsonWithTimeout(API_URL, { url });
  if (!res.ok) throw new Error(`API ${res.status}`);
  const normalized = normalizeResult(await res.json());
  const thresholded = withThreshold(normalized);
  return {
    ...thresholded,
    inputType: "Website",
    reasons: explainUrl(url, thresholded, false)
  };
}

async function detectEmail(text) {
  const res = await postJsonWithTimeout(API_EMAIL, { text });
  if (!res.ok) throw new Error(`API ${res.status}`);
  const normalized = normalizeResult(await res.json());
  const thresholded = withThreshold(normalized);
  if (
    Number.isFinite(normalized.heuristicScore) &&
    Number.isFinite(normalized.modelRawScore) &&
    normalized.heuristicScore > normalized.modelRawScore
  ) {
    thresholded.reasons = [`Heuristic risk boost applied (${(normalized.heuristicScore * 100).toFixed(1)}%).`];
  }
  if (Number.isFinite(normalized.benignDiscount) && normalized.benignDiscount > 0) {
    thresholded.reasons = [...(thresholded.reasons || []), `Benign-context discount applied (${(normalized.benignDiscount * 100).toFixed(1)}%).`];
  }
  return {
    ...thresholded,
    inputType: "Email",
    reasons: [...(thresholded.reasons || []), ...explainEmail(text, thresholded)].slice(0, 4)
  };
}

async function setBadge(tabId, result) {
  if (result.prediction === "phishing") {
    await chrome.action.setBadgeText({ text: "!", tabId });
    await chrome.action.setBadgeBackgroundColor({ color: "#d93025", tabId });
  } else {
    await chrome.action.setBadgeText({ text: "OK", tabId });
    await chrome.action.setBadgeBackgroundColor({ color: "#188038", tabId });
  }
}

async function notifyEmailDesktop(result) {
  try {
    const phishing = result?.prediction === "phishing";
    const conf = `${((Number(result?.confidence || 0)) * 100).toFixed(1)}%`;
    await chrome.notifications.create({
      type: "basic",
      iconUrl: "assets/icon128.png",
      title: phishing ? "Phishing Shield: Email Risk" : "Phishing Shield: Email Safe",
      message: phishing
        ? `Possible phishing email detected. Confidence: ${conf}`
        : `Email appears safe. Confidence: ${conf}`
    });
  } catch {
    // Ignore notification failures on unsupported contexts.
  }
}

async function notifyWebsiteVisit(url) {
  try {
    const host = getHostname(url) || "website";
    await chrome.notifications.create({
      type: "basic",
      iconUrl: "assets/icon128.png",
      title: "Phishing Shield: Website Scan",
      message: `Scanning ${host} for phishing indicators...`
    });
  } catch {
    // Ignore notification failures.
  }
}

async function notifyWebsiteResult(url, result) {
  try {
    const host = getHostname(url) || "website";
    const phishing = result?.prediction === "phishing";
    const conf = `${((Number(result?.confidence || 0)) * 100).toFixed(1)}%`;
    await chrome.notifications.create({
      type: "basic",
      iconUrl: "assets/icon128.png",
      title: phishing ? "Phishing Shield: Website Risk" : "Phishing Shield: Website Safe",
      message: phishing
        ? `${host} looks suspicious. Confidence: ${conf}`
        : `${host} appears safe. Confidence: ${conf}`
    });
  } catch {
    // Ignore notification failures.
  }
}

async function notifyTabResult(tabId, payload) {
  if (!Number.isInteger(tabId)) return false;

  try {
    await chrome.tabs.sendMessage(tabId, { type: "PHISHING_RESULT", payload });
    return true;
  } catch {
    // Fallback for pages where content script is unavailable.
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (result) => {
        const old = document.getElementById("phishing-shield-banner");
        if (old) old.remove();

        const phishing = result?.prediction === "phishing";
        const inputType = String(result?.inputType || "").toLowerCase();
        const noun = inputType === "email" ? "email" : "website";
        const conf = `${((Number(result?.confidence || 0)) * 100).toFixed(1)}%`;
        const message = phishing
          ? `Warning: Possible phishing ${noun} detected`
          : `This ${noun} appears safe`;

        const wrap = document.createElement("div");
        wrap.id = "phishing-shield-banner";
        wrap.innerHTML = `
          <div style="position:fixed;top:12px;right:12px;z-index:2147483647;max-width:360px;background:${phishing ? "#c62828" : "#2e7d32"};color:#fff;padding:12px 14px;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.28);font-family:'Segoe UI',Tahoma,sans-serif;">
            <div style="font-weight:700;font-size:14px;">${message}</div>
            <div style="opacity:.95;font-size:12px;margin-top:6px;">Confidence: ${conf}</div>
          </div>`;

        (document.body || document.documentElement).appendChild(wrap);
        setTimeout(() => {
          const banner = document.getElementById("phishing-shield-banner");
          if (banner) banner.remove();
        }, 8000);
      },
      args: [payload]
    });
    return true;
  } catch {
    // Ignore on restricted pages.
  }

  return false;
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab?.url || !/^https?:\/\//i.test(tab.url)) return;

  (async () => {
    try {
      const previousUrl = lastWebsiteNotifiedByTab.get(tabId);
      if (previousUrl !== tab.url) {
        lastWebsiteNotifiedByTab.set(tabId, tab.url);
        await notifyWebsiteVisit(tab.url);
      }

      const result = await detectUrl(tab.url);
      await setBackendOnline(true);
      await chrome.storage.local.set({ [`lastResult_${tabId}`]: { url: tab.url, ...result } });
      await setBadge(tabId, result);
      await addHistory({
        timestamp: new Date().toISOString(),
        inputType: "Website",
        source: "auto-url",
        snippet: toSnippet(tab.url),
        prediction: result.prediction,
        confidence: result.confidence,
        reasons: result.reasons || []
      });
      await notifyTabResult(tabId, { url: tab.url, ...result });
      await notifyWebsiteResult(tab.url, result);
    } catch {
      await setBackendOnline(false);
      await chrome.action.setBadgeText({ text: "?", tabId });
      await chrome.action.setBadgeBackgroundColor({ color: "#f29900", tabId });
    }
  })();
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "DETECT_URL") {
        const result = await detectUrl(msg.url);
        await setBackendOnline(true);
        let targetTabId = Number.isInteger(msg.tabId) ? msg.tabId : null;
        if (!targetTabId && Number.isInteger(sender?.tab?.id)) {
          targetTabId = sender.tab.id;
        }
        if (!targetTabId) {
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          targetTabId = tab?.id;
        }
        const notified = await notifyTabResult(targetTabId, { url: msg.url, ...result });
        if (Number.isInteger(targetTabId)) {
          await chrome.storage.local.set({ [`lastResult_${targetTabId}`]: { url: msg.url, ...result } });
          await setBadge(targetTabId, result);
        }
        await addHistory({
          timestamp: new Date().toISOString(),
          inputType: "Website",
          source: msg.source || "manual-url",
          snippet: toSnippet(msg.url),
          prediction: result.prediction,
          confidence: result.confidence,
          reasons: result.reasons || []
        });
        sendResponse({ success: true, data: { ...result, notified } });
        return;
      }
      if (msg?.type === "DETECT_EMAIL") {
        const result = await detectEmail(msg.text);
        await setBackendOnline(true);
        await notifyEmailDesktop(result);
        let targetTabId = Number.isInteger(msg.tabId) ? msg.tabId : null;
        if (!targetTabId && Number.isInteger(sender?.tab?.id)) {
          targetTabId = sender.tab.id;
        }
        if (!targetTabId) {
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          targetTabId = tab?.id;
        }
        const notified = await notifyTabResult(targetTabId, { text: msg.text, ...result });
        if (Number.isInteger(targetTabId)) {
          await chrome.storage.local.set({ [`lastResult_${targetTabId}`]: { text: msg.text, ...result } });
          await setBadge(targetTabId, result);
        }
        await addHistory({
          timestamp: new Date().toISOString(),
          inputType: "Email",
          source: msg.source || "manual-email",
          snippet: toSnippet(msg.text),
          prediction: result.prediction,
          confidence: result.confidence,
          reasons: result.reasons || []
        });
        sendResponse({ success: true, data: { ...result, notified } });
        return;
      }
      if (msg?.type === "HEALTH_CHECK") {
        sendResponse({ success: true, data: await checkBackendHealth() });
        return;
      }
      if (msg?.type === "GET_BACKEND_STATUS") {
        sendResponse({ success: true, data: { online: backendOnline } });
        return;
      }
      if (msg?.type === "GET_THRESHOLD") {
        sendResponse({ success: true, data: { threshold: detectionThreshold } });
        return;
      }
      if (msg?.type === "SET_THRESHOLD") {
        const t = clampThreshold(msg.value);
        detectionThreshold = t;
        await chrome.storage.local.set({ [DETECTION_THRESHOLD_KEY]: t });
        sendResponse({ success: true, data: { threshold: t } });
        return;
      }
      if (msg?.type === "GET_HISTORY") {
        const r = await chrome.storage.local.get({ [SCAN_HISTORY_KEY]: [] });
        sendResponse({ success: true, data: Array.isArray(r[SCAN_HISTORY_KEY]) ? r[SCAN_HISTORY_KEY] : [] });
        return;
      }
      if (msg?.type === "CLEAR_HISTORY") {
        await chrome.storage.local.set({ [SCAN_HISTORY_KEY]: [] });
        sendResponse({ success: true, data: [] });
        return;
      }
      if (msg?.type === "GET_LAST_RESULT") {
        const key = `lastResult_${msg.tabId}`;
        const data = await chrome.storage.local.get(key);
        sendResponse({ success: true, data: data[key] || null });
        return;
      }
      sendResponse({ success: false, error: "Unknown message type" });
    } catch (err) {
      await setBackendOnline(false);
      sendResponse({ success: false, error: err?.message || "Request failed" });
    }
  })();

  return true;
});
