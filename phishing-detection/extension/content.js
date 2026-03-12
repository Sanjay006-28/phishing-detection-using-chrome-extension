(() => {
if (globalThis.__phishingShieldContentInitialized) return;
globalThis.__phishingShieldContentInitialized = true;

function removeExisting() {
  const old = document.getElementById("phishing-shield-banner");
  if (old) old.remove();
}

function showBanner(result) {
  removeExisting();
  const phishing = result?.prediction === "phishing";
  const inputType = String(result?.inputType || "").toLowerCase();
  const noun = inputType === "email" ? "email" : "website";
  const message = phishing
    ? `⚠️ Warning: Possible phishing ${noun} detected`
    : `✅ This ${noun} appears safe`;
  const conf = `${((Number(result?.confidence || 0)) * 100).toFixed(1)}%`;

  const box = document.createElement("div");
  box.id = "phishing-shield-banner";
  box.innerHTML = `
    <div style="position:fixed;top:12px;right:12px;z-index:2147483647;max-width:350px;
      background:${phishing ? "#c62828" : "#2e7d32"};color:#fff;padding:12px 14px;border-radius:10px;
      box-shadow:0 8px 24px rgba(0,0,0,.28);font-family:'Segoe UI',Tahoma,sans-serif;">
      <div style="font-weight:700;font-size:14px;">${message}</div>
      <div style="opacity:.95;font-size:12px;margin-top:6px;">Confidence: ${conf}</div>
      <button id="phishing-shield-dismiss" style="margin-top:8px;background:rgba(255,255,255,.2);border:1px solid rgba(255,255,255,.45);color:#fff;padding:4px 8px;border-radius:6px;cursor:pointer;">Dismiss</button>
    </div>`;

  (document.body || document.documentElement).appendChild(box);
  const btn = document.getElementById("phishing-shield-dismiss");
  if (btn) btn.addEventListener("click", removeExisting);

  setTimeout(removeExisting, 8000);
}

function firstText(selectors) {
  for (const sel of selectors) {
    const el = document.querySelector(sel);
    const text = el?.innerText?.trim();
    if (text) return text;
  }
  return "";
}

function cleanText(text) {
  return String(text || "").replace(/\s+/g, " ").trim();
}

function isVisible(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  return style.display !== "none" && style.visibility !== "hidden";
}

function collectCandidateText(root, selectors, maxItems = 6) {
  const parts = [];
  for (const sel of selectors) {
    const nodes = Array.from(root.querySelectorAll(sel));
    for (const node of nodes) {
      if (!isVisible(node)) continue;
      const text = cleanText(node.innerText || node.textContent || "");
      if (text.length < 20) continue;
      parts.push(text);
      if (parts.length >= maxItems) break;
    }
    if (parts.length >= maxItems) break;
  }

  if (!parts.length) return "";
  parts.sort((a, b) => b.length - a.length);
  return parts[0];
}

function collectLongestVisibleText(root, selectors, maxNodes = 20) {
  const candidates = [];
  for (const sel of selectors) {
    const nodes = Array.from(root.querySelectorAll(sel));
    for (const node of nodes) {
      if (!isVisible(node)) continue;
      const text = cleanText(node.innerText || node.textContent || "");
      if (text.length < 40) continue;
      candidates.push(text);
      if (candidates.length >= maxNodes) break;
    }
    if (candidates.length >= maxNodes) break;
  }
  if (!candidates.length) return "";
  candidates.sort((a, b) => b.length - a.length);
  return candidates[0];
}

function extractFromDocument(doc, host) {
  const gmailSubject = [
    "h2.hP",
    "h2[data-thread-perm-id]",
    "div[role='main'] h2[tabindex='-1']",
    "div[role='main'] h2"
  ];
  const gmailBody = [
    "div.a3s.aiL",
    "div.a3s",
    "div[role='listitem'] div[dir='ltr']",
    "div[data-message-id] div[dir='ltr']",
    "div[data-message-id]"
  ];

  const outlookSubject = [
    "span[data-testid='message-subject']",
    "div[data-testid='message-subject']",
    "div[aria-label='Reading pane'] h1",
    "div[aria-label='Reading pane'] [role='heading'][aria-level='1']",
    "div[aria-label='Reading pane'] [role='heading']",
    "div[role='heading'][aria-level='2']",
    "div[role='heading']"
  ];
  const outlookBody = [
    "div[data-testid='message-body']",
    "div[data-testid='ReadMessageContainer'] div[dir='ltr']",
    "div[data-testid='ReadMessageContainer'] [role='document']",
    "div[aria-label='Reading pane'] [role='document']",
    "div[aria-label='Reading pane'] div[dir='ltr']",
    "div[data-app-section='MailReadCompose'] [role='document']",
    "div[data-app-section='MailReadCompose'] div[dir='ltr']",
    "div[aria-label='Message body']",
    "div[aria-label*='Message body'] div[dir='ltr']",
    "div[role='document']",
    "div[aria-label*='Message body']"
  ];

  const yahooSubject = ["h2[data-test-id='message-group-subject-text']", "h2.thread-subject"];
  const yahooBody = ["div[data-test-id='message-view-body']", "div.msg-body"];

  let subject = "";
  let body = "";

  if (host.includes("mail.google.com")) {
    subject = collectCandidateText(doc, gmailSubject, 2) || firstText(gmailSubject);
    body = collectCandidateText(doc, gmailBody, 8) || firstText(gmailBody);
  } else if (
    host.includes("outlook.live.com") ||
    host.includes("outlook.office.com") ||
    host.includes("outlook.office365.com") ||
    host.includes("outlook.com")
  ) {
    subject = collectCandidateText(doc, outlookSubject, 2) || firstText(outlookSubject);
    body = collectCandidateText(doc, outlookBody, 8) || firstText(outlookBody);
  } else if (host.includes("mail.yahoo.com")) {
    subject = collectCandidateText(doc, yahooSubject, 2) || firstText(yahooSubject);
    body = collectCandidateText(doc, yahooBody, 8) || firstText(yahooBody);
  }

  if (!body) {
    body = collectCandidateText(doc, ["article", "main", "[role='main']", "div[role='document']", "body"], 8);
  }
  if (!subject) {
    subject = collectCandidateText(doc, ["h1", "h2", "div[role='heading']"], 2);
  }

  return {
    subject: cleanText(subject),
    body: cleanText(body)
  };
}

function extractEmailText() {
  const host = location.hostname.toLowerCase();

  let { subject, body } = extractFromDocument(document, host);

  if ((!subject && !body) || body.length < 20) {
    const frames = Array.from(document.querySelectorAll("iframe"));
    for (const frame of frames) {
      try {
        const fdoc = frame.contentDocument;
        if (!fdoc) continue;
        const fromFrame = extractFromDocument(fdoc, host);
        if (!subject && fromFrame.subject) subject = fromFrame.subject;
        if (fromFrame.body && fromFrame.body.length > body.length) body = fromFrame.body;
      } catch {
        // Ignore cross-origin frames.
      }
    }
  }

  if (
    body.length < 20 &&
    (host.includes("outlook.live.com") || host.includes("outlook.office.com") || host.includes("outlook.office365.com") || host.includes("outlook.com"))
  ) {
    const pane = document.querySelector(
      "div[aria-label='Reading pane'], div[data-testid='ReadMessageContainer'], div[data-app-section='MailReadCompose']"
    );
    const paneText = cleanText(pane?.innerText || pane?.textContent || "");
    if (paneText.length > body.length) {
      body = paneText;
      if (!subject) {
        const firstLine = paneText.split(/\n|\r/).map((x) => cleanText(x)).find(Boolean);
        subject = firstLine || subject;
      }
    }
  }

  if (body.length < 30) {
    const broad = collectLongestVisibleText(document, [
      "div[aria-label='Reading pane']",
      "div[data-testid='ReadMessageContainer']",
      "div[data-app-section='MailReadCompose']",
      "div[data-message-id]",
      "div.a3s.aiL",
      "div[role='document']",
      "article",
      "main"
    ]);
    if (broad.length > body.length) {
      body = broad;
    }
  }

  const text = cleanText(`${subject}\n\n${body}`).slice(0, 12000);
  return { text, source: host || "unknown" };
}

var autoEmailDebounceTimer = globalThis.__phishingShieldAutoEmailDebounceTimer || null;
var lastEmailFingerprint = globalThis.__phishingShieldLastEmailFingerprint || "";

function isMailHost(host) {
  const h = String(host || "").toLowerCase();
  return (
    h.includes("mail.google.com") ||
    h.includes("outlook.live.com") ||
    h.includes("outlook.office.com") ||
    h.includes("outlook.office365.com") ||
    h.includes("outlook.com")
  );
}

function buildFingerprint(emailText) {
  const normalized = cleanText(emailText).slice(0, 220);
  return `${location.href}::${normalized}`;
}

function sendEmailForDetection(text) {
  try {
    chrome.runtime.sendMessage(
      {
        type: "DETECT_EMAIL",
        text,
        source: "auto-email-open"
      },
      () => {
        // Ignore disconnects that happen after extension reload/update.
        void chrome.runtime?.lastError;
      }
    );
    return true;
  } catch {
    return false;
  }
}

function tryAutoScanOpenedEmail() {
  if (!isMailHost(location.hostname)) return;

  try {
    const extracted = extractEmailText();
    const text = cleanText(extracted?.text || "");
    if (text.length < 30) return;

    const fp = buildFingerprint(text);
    if (fp === lastEmailFingerprint) return;
    lastEmailFingerprint = fp;
    globalThis.__phishingShieldLastEmailFingerprint = lastEmailFingerprint;

    if (!sendEmailForDetection(text)) {
      if (autoEmailDebounceTimer) clearTimeout(autoEmailDebounceTimer);
    }
  } catch {
    // Ignore transient DOM/context issues while mail UI is changing.
  }
}

function scheduleAutoScan() {
  if (autoEmailDebounceTimer) clearTimeout(autoEmailDebounceTimer);
  autoEmailDebounceTimer = setTimeout(tryAutoScanOpenedEmail, 700);
  globalThis.__phishingShieldAutoEmailDebounceTimer = autoEmailDebounceTimer;
}

function startAutoEmailMonitor() {
  if (!isMailHost(location.hostname)) return;

  let lastHref = location.href;
  setInterval(() => {
    if (location.href !== lastHref) {
      lastHref = location.href;
      scheduleAutoScan();
    }
  }, 500);

  const observer = new MutationObserver(() => {
    scheduleAutoScan();
  });

  observer.observe(document.documentElement || document.body, {
    childList: true,
    subtree: true,
    characterData: false,
    attributes: false
  });

  // Initial attempt for already-open message view.
  scheduleAutoScan();

  document.addEventListener("click", () => {
    // Message-open events in Gmail/Outlook are click-driven; run delayed checks.
    scheduleAutoScan();
    setTimeout(scheduleAutoScan, 450);
    setTimeout(scheduleAutoScan, 1200);
  }, true);

  setInterval(() => {
    scheduleAutoScan();
  }, 6000);
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "PHISHING_RESULT") {
    if (msg?.payload) showBanner(msg.payload);
    return;
  }

  if (msg?.type === "EXTRACT_EMAIL_TEXT") {
    try {
      const data = extractEmailText();
      if (!data.text) {
        sendResponse({ success: false, error: "No email content found on this page" });
        return;
      }
      sendResponse({ success: true, data });
    } catch {
      sendResponse({ success: false, error: "Failed to extract email text" });
    }
  }
});

startAutoEmailMonitor();
})();
