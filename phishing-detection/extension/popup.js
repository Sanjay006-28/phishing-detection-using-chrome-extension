const $ = (s) => document.querySelector(s);

const statusEl = $("#status");
const backendBadgeEl = $("#backendBadge");
const backendTextEl = $("#backendText");
const currentUrlEl = $("#currentUrl");
const urlResultEl = $("#urlResult");
const emailResultEl = $("#emailResult");
const historyListEl = $("#historyList");
const emailModeAutoBtn = $("#emailModeAuto");
const emailModeManualBtn = $("#emailModeManual");
const emailAutoSection = $("#emailAutoSection");
const emailManualSection = $("#emailManualSection");
const emailPreviewEl = $("#emailPreview");
const thresholdSliderEl = $("#thresholdSlider");
const thresholdValueEl = $("#thresholdValue");

let lastAutoEmailText = "";

function setStatus(msg) {
  statusEl.textContent = msg;
}

function updateBackendBadge(online) {
  backendBadgeEl.classList.remove("online", "offline");
  backendBadgeEl.classList.add(online ? "online" : "offline");
  backendTextEl.textContent = online ? "Backend: connected" : "Backend: disconnected";
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function showResult(container, result, inputType = "website") {
  const phishing = result?.prediction === "phishing";
  const conf = `${((Number(result?.confidence || 0)) * 100).toFixed(1)}%`;
  const isEmail = String(inputType).toLowerCase() === "email";
  const noun = isEmail ? "email" : "website";
  const title = phishing
    ? `Warning: Possible phishing ${noun} detected`
    : `This ${noun} appears safe`;
  const riskLevel = phishing
    ? (Number(result?.confidence || 0) >= 0.85 ? "HIGH" : "MEDIUM")
    : (Number(result?.confidence || 0) >= 0.85 ? "LOW" : "MEDIUM");
  const reasons = Array.isArray(result?.reasons) && result.reasons.length
    ? result.reasons.slice(0, 4)
    : [phishing ? "Detected suspicious signals by model and heuristics." : "No high-risk patterns detected."];
  const reasonsHtml = reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("");
  const copyText = [
    `${phishing ? "PHISHING" : "SAFE"} - ${isEmail ? "Email" : "Website"}`,
    `Confidence: ${conf}`,
    `Risk Level: ${riskLevel}`,
    `Reasons: ${reasons.join(" | ")}`
  ].join("\n");

  container.classList.remove("hidden", "safe", "phishing");
  container.classList.add(phishing ? "phishing" : "safe");
  container.innerHTML = `${phishing ? "⚠️" : "✅"} ${title}<small>Input Type: ${isEmail ? "Email" : "Website"} | Confidence: ${conf} | Risk: ${riskLevel}</small><ul class="reasons">${reasonsHtml}</ul><div class="result-actions"><button class="mini-btn copy-result">Copy Result</button></div>`;
  const copyBtn = container.querySelector(".copy-result");
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(copyText);
        setStatus("Result copied");
      } catch {
        setStatus("Copy failed");
      }
    });
  }
}

function send(msg) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (resp) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!resp?.success) {
        reject(new Error(resp?.error || "Request failed"));
        return;
      }
      resolve(resp.data);
    });
  });
}

function downloadText(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function renderHistory(items) {
  const list = Array.isArray(items) ? items : [];
  historyListEl.innerHTML = "";
  if (!list.length) {
    historyListEl.innerHTML = "<div class=\"history-item\">No scans yet.</div>";
    return;
  }

  for (const item of list) {
    const row = document.createElement("div");
    row.className = `history-item ${item.prediction === "phishing" ? "phishing" : "safe"}`;
    const when = item.timestamp ? new Date(item.timestamp).toLocaleString() : "";
    row.innerHTML = `
      <div class="top"><span>${item.prediction === "phishing" ? "⚠️ Phishing" : "✅ Safe"}</span><span>${escapeHtml(item.inputType || "")}</span></div>
      <div>${escapeHtml(item.snippet || "")}</div>
      <div style="margin-top:4px;opacity:.85;">${escapeHtml(when)} | ${(Number(item.confidence || 0) * 100).toFixed(1)}%</div>
    `;
    historyListEl.appendChild(row);
  }
}

async function refreshHistory() {
  try {
    const history = await send({ type: "GET_HISTORY" });
    renderHistory(history);
  } catch {
    renderHistory([]);
  }
}

function setEmailMode(mode) {
  const auto = mode === "auto";
  emailModeAutoBtn.classList.toggle("active", auto);
  emailModeManualBtn.classList.toggle("active", !auto);
  emailAutoSection.classList.toggle("active", auto);
  emailManualSection.classList.toggle("active", !auto);
}

function activateEmailSection() {
  document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".section").forEach((s) => s.classList.remove("active"));
  const emailTab = document.querySelector('.tab[data-section="email"]');
  if (emailTab) emailTab.classList.add("active");
  const emailSection = document.querySelector("#section-email");
  if (emailSection) emailSection.classList.add("active");
}

function focusResultCard(el) {
  if (!el) return;
  el.scrollIntoView({ behavior: "smooth", block: "nearest" });
  el.style.outline = "2px solid rgba(66, 184, 255, 0.55)";
  setTimeout(() => {
    el.style.outline = "";
  }, 900);
}

function sendToTab(tabId, msg) {
  return new Promise((resolve, reject) => {
    const handleResponse = (resp) => {
      if (!resp?.success) {
        reject(new Error(resp?.error || "Could not extract email text from this page"));
        return;
      }
      resolve(resp.data);
    };

    chrome.tabs.sendMessage(tabId, msg, async (resp) => {
      const err = chrome.runtime.lastError;
      if (!err) {
        handleResponse(resp);
        return;
      }

      // If content script is not attached (common for already-open tabs), inject and retry once.
      if (!/Receiving end does not exist/i.test(err.message || "")) {
        reject(new Error(err.message));
        return;
      }

      reject(new Error("Mail page script is not ready. Refresh the Gmail/Outlook tab once, then try again."));
    });
  });
}

async function loadCurrentUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentUrlEl.textContent = tab?.url || "No active URL";
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".section").forEach((s) => s.classList.remove("active"));
    btn.classList.add("active");
    $(`#section-${btn.dataset.section}`).classList.add("active");
  });
});

$("#checkCurrent").addEventListener("click", async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) throw new Error("No active tab URL found");
    const result = await send({ type: "DETECT_URL", url: tab.url, source: "current-url", tabId: tab.id });
    showResult(urlResultEl, result, "website");
    await refreshHistory();
    setStatus(result.notified ? "URL scan complete" : "URL scan complete (page alert unavailable on this tab)");
  } catch (e) {
    setStatus(e.message);
  }
});

$("#checkUrl").addEventListener("click", async () => {
  try {
    const url = $("#urlInput").value.trim();
    if (!url) throw new Error("Enter a URL first");
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const result = await send({ type: "DETECT_URL", url, source: "manual-url", tabId: tab?.id });
    showResult(urlResultEl, result, "website");
    await refreshHistory();
    setStatus(result.notified ? "Manual URL scan complete" : "Manual URL scan complete (page alert unavailable on this tab)");
  } catch (e) {
    setStatus(e.message);
  }
});

emailModeAutoBtn.addEventListener("click", () => setEmailMode("auto"));
emailModeManualBtn.addEventListener("click", () => setEmailMode("manual"));

$("#extractEmailAuto").addEventListener("click", async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error("No active tab found");
    const extracted = await sendToTab(tab.id, { type: "EXTRACT_EMAIL_TEXT" });
    const text = String(extracted?.text || "").trim();
    if (!text) throw new Error("No email content found on this page");
    lastAutoEmailText = text;
    emailPreviewEl.value = text.slice(0, 4000);
    setStatus("Email content extracted. Review preview and scan.");
  } catch (e) {
    setStatus(e.message);
  }
});

$("#checkEmailAuto").addEventListener("click", async () => {
  try {
    const text = (lastAutoEmailText || emailPreviewEl.value || "").trim();
    if (!text) throw new Error("Extract email first before scanning.");
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const result = await send({ type: "DETECT_EMAIL", text, source: "auto-email", tabId: tab?.id });
    activateEmailSection();
    showResult(emailResultEl, result, "email");
    focusResultCard(emailResultEl);
    await refreshHistory();
    setStatus(result.notified ? "Automatic email scan complete" : "Automatic email scan complete (page alert unavailable on this tab)");
  } catch (e) {
    setStatus(e.message);
  }
});

$("#checkEmailManual").addEventListener("click", async () => {
  try {
    const text = $("#emailInput").value.trim();
    if (!text) throw new Error("Enter email text first");
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const result = await send({ type: "DETECT_EMAIL", text, source: "manual-email", tabId: tab?.id });
    activateEmailSection();
    showResult(emailResultEl, result, "email");
    focusResultCard(emailResultEl);
    await refreshHistory();
    setStatus(result.notified ? "Manual email scan complete" : "Manual email scan complete (page alert unavailable on this tab)");
  } catch (e) {
    setStatus(e.message);
  }
});

thresholdSliderEl.addEventListener("input", () => {
  thresholdValueEl.textContent = Number(thresholdSliderEl.value).toFixed(2);
});

thresholdSliderEl.addEventListener("change", async () => {
  try {
    const value = Number(thresholdSliderEl.value);
    const res = await send({ type: "SET_THRESHOLD", value });
    thresholdSliderEl.value = String(res.threshold);
    thresholdValueEl.textContent = Number(res.threshold).toFixed(2);
    setStatus("Threshold updated");
  } catch (e) {
    setStatus(e.message);
  }
});

$("#exportSuspiciousJson").addEventListener("click", async () => {
  try {
    const history = await send({ type: "GET_HISTORY" });
    const suspicious = history.filter((x) => x.prediction === "phishing");
    if (!suspicious.length) throw new Error("No suspicious items to export");
    downloadText(`suspicious_report_${Date.now()}.json`, JSON.stringify(suspicious, null, 2), "application/json");
    setStatus("Suspicious JSON exported");
  } catch (e) {
    setStatus(e.message);
  }
});

$("#exportSuspiciousCsv").addEventListener("click", async () => {
  try {
    const history = await send({ type: "GET_HISTORY" });
    const suspicious = history.filter((x) => x.prediction === "phishing");
    if (!suspicious.length) throw new Error("No suspicious items to export");
    const header = "timestamp,inputType,source,prediction,confidence,snippet";
    const rows = suspicious.map((x) => [
      x.timestamp,
      x.inputType,
      x.source,
      x.prediction,
      x.confidence,
      `"${String(x.snippet || "").replaceAll('"', '""')}"`
    ].join(","));
    downloadText(`suspicious_report_${Date.now()}.csv`, [header, ...rows].join("\n"), "text/csv");
    setStatus("Suspicious CSV exported");
  } catch (e) {
    setStatus(e.message);
  }
});

$("#clearHistory").addEventListener("click", async () => {
  try {
    await send({ type: "CLEAR_HISTORY" });
    await refreshHistory();
    setStatus("History cleared");
  } catch (e) {
    setStatus(e.message);
  }
});

async function init() {
  setEmailMode("auto");
  await loadCurrentUrl();
  emailPreviewEl.value = "";

  try {
    const health = await send({ type: "HEALTH_CHECK" });
    updateBackendBadge(Boolean(health?.online));
  } catch {
    updateBackendBadge(false);
  }

  try {
    const t = await send({ type: "GET_THRESHOLD" });
    thresholdSliderEl.value = String(t.threshold);
    thresholdValueEl.textContent = Number(t.threshold).toFixed(2);
  } catch {
    thresholdValueEl.textContent = "0.50";
  }

  await refreshHistory();

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      const last = await send({ type: "GET_LAST_RESULT", tabId: tab.id });
      if (last?.prediction) {
        const isEmail = String(last.inputType || "").toLowerCase() === "email";
        showResult(isEmail ? emailResultEl : urlResultEl, last, isEmail ? "email" : "website");
      }
    }
  } catch {
    setStatus("Backend unavailable");
  }

}

init();
