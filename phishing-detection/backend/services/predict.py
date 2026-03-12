import pickle
import re
import time
from pathlib import Path

import numpy as np
from tensorflow.keras.models import load_model

from .preprocess import email_to_sequence, extract_url_features

STATE = {
    "email_model": None,
    "url_model": None,
    "email_tokenizer": None,
    "load_time_ms": None,
    "artifacts": {},
}


def _find_file(candidates):
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError(f"Missing file. Tried: {candidates}")


def load_artifacts() -> None:
    t0 = time.perf_counter()
    backend_root = Path(__file__).resolve().parents[1]
    email_candidates = [backend_root / "models" / "email_model.h5"]
    url_candidates = [backend_root / "models" / "url_model.h5"]
    tokenizer_candidates = [backend_root / "tokenizer" / "email_tokenizer.pkl"]

    try:
        email_model_path = _find_file(email_candidates)
        url_model_path = _find_file(url_candidates)
        tokenizer_path = _find_file(tokenizer_candidates)

        STATE["email_model"] = load_model(email_model_path)
        STATE["url_model"] = load_model(url_model_path)
        with open(tokenizer_path, "rb") as f:
            STATE["email_tokenizer"] = pickle.load(f)

        STATE["artifacts"] = {
            "email_model": str(email_model_path),
            "url_model": str(url_model_path),
            "email_tokenizer": str(tokenizer_path),
        }
        STATE["load_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        print(f"[startup] Artifacts loaded in {STATE['load_time_ms']} ms")
    except Exception as exc:
        details = (
            f"email model candidates={email_candidates}; "
            f"url model candidates={url_candidates}; "
            f"tokenizer candidates={tokenizer_candidates}"
        )
        raise RuntimeError(f"Failed to load artifacts. {details}. Original error: {exc}") from exc


def get_runtime_info() -> dict:
    return {
        "loaded": STATE["email_model"] is not None and STATE["url_model"] is not None and STATE["email_tokenizer"] is not None,
        "load_time_ms": STATE["load_time_ms"],
        "artifacts": STATE["artifacts"],
    }


def _ensure_loaded() -> None:
    if STATE["email_model"] is None or STATE["url_model"] is None or STATE["email_tokenizer"] is None:
        raise RuntimeError("Artifacts not loaded. Start backend after training models and tokenizer.")


def _format(score: float) -> dict:
    label = "phishing" if score >= 0.5 else "safe"
    confidence = score if label == "phishing" else 1 - score
    return {
        "prediction": label,
        "confidence": round(float(confidence), 4),
        "raw_score": round(float(score), 4),
    }


def _email_heuristic_score(text: str) -> float:
    lower = str(text or "").lower()
    score = 0.0

    trusted_google_notice = (
        bool(re.search(r"no-reply@accounts\.google\.com|accounts\.google\.com", lower))
        and "new sign-in" in lower
        and "if this was you" in lower
    )
    trusted_microsoft_notice = (
        bool(re.search(r"account-security-noreply@accountprotection\.microsoft\.com|accountprotection\.microsoft\.com", lower))
        and ("unusual sign-in" in lower or "recent activity" in lower)
    )
    trusted_notice = trusted_google_notice or trusted_microsoft_notice

    # Keep trusted-provider security notices low-risk unless they contain strong lure signals.
    if trusted_notice:
        has_attachment_lure = bool(re.search(r"\b(zip|rar|7z|iso|html|htm|docm|xlsm|js|vbs|exe)\b", lower))
        has_credential_lure = bool(re.search(r"verify your password|enter password|confirm password|login now|update payment", lower))
        if not has_attachment_lure and not has_credential_lure:
            return 0.05

    urgent_count = len(re.findall(r"urgent|immediately|asap|verify|revalidation|action required|security alert", lower))
    finance_count = len(re.findall(r"bank|paypal|account|wallet|crypto|btc|eth|payment", lower))
    sensitive_count = len(re.findall(r"otp|pin|cvv|ssn|social security|credit card|password", lower))
    threat_count = len(re.findall(r"suspend|suspension|deactivate|failure to complete|limited access|temporary suspension", lower))
    impersonation_count = len(re.findall(r"it support|helpdesk|admin team|university|office 365|mail team", lower))
    link_like_count = len(re.findall(r"https?://|www\.|htxps?://|hxxps?://|\b[a-z0-9-]+\.(com|net|org|edu|info|io)/[a-z0-9]", str(text or ""), re.IGNORECASE))
    invoice_count = len(re.findall(r"invoice|billing|payment|transaction|receipt|accounts? department|wire transfer|remittance", lower))
    attachment_count = len(re.findall(r"attachment|attached|download|document", lower))
    risky_attachment = bool(re.search(r"\b(zip|rar|7z|iso|html|htm|docm|xlsm|js|vbs|exe)\b", lower))

    if urgent_count > 0:
        score += min(0.25, 0.08 * urgent_count)
    if finance_count > 0 or sensitive_count > 0:
        score += 0.2
    if threat_count > 0:
        score += min(0.25, 0.1 * threat_count)
    if impersonation_count > 0:
        score += min(0.15, 0.06 * impersonation_count)
    if link_like_count > 0:
        score += 0.25
    if invoice_count > 0:
        score += min(0.2, 0.07 * invoice_count)
    if attachment_count > 0 and invoice_count > 0:
        score += 0.2
    elif attachment_count > 0:
        score += 0.08
    if risky_attachment and (attachment_count > 0 or invoice_count > 0):
        score += 0.2

    return round(min(0.95, score), 4)


def _email_benign_discount(text: str) -> float:
    t = str(text or "")
    lower = t.lower()
    normalized = lower.replace("no action required", "")

    benign_hits = len(re.findall(r"\b(hello|hi|thanks|thank you|regards|meeting|agenda|notes|team|schedule|tomorrow|today|attached)\b", lower))
    phishing_hits = len(re.findall(r"urgent|immediately|asap|verify|revalidation|action required|security alert|password|otp|pin|suspend|suspension|deactivate", normalized))
    link_hits = len(re.findall(r"https?://|www\.|htxps?://|hxxps?://", t, re.IGNORECASE))
    invoice_lure_hits = len(re.findall(r"invoice|billing|payment|transaction|receipt|accounts? department|wire transfer|remittance", lower))
    attachment_lure_hits = len(re.findall(r"attachment|attached|document|download", lower))
    risky_attachment = bool(re.search(r"\b(zip|rar|7z|iso|html|htm|docm|xlsm|js|vbs|exe)\b", lower))

    # Do not apply benign discount to common financial-attachment lure patterns.
    if invoice_lure_hits > 0 or (attachment_lure_hits > 0 and risky_attachment):
        return 0.0

    if benign_hits >= 2 and phishing_hits == 0 and link_hits == 0:
        return 0.65
    if benign_hits >= 1 and phishing_hits == 0 and link_hits == 0:
        return 0.45
    return 0.0


def _trusted_notice_discount(text: str) -> float:
    lower = str(text or "").lower()

    # Keep invoice/attachment lure handling strict.
    invoice_or_payment_lure = bool(re.search(r"invoice|billing|payment|transaction|receipt|wire transfer|remittance", lower))
    risky_attachment = bool(re.search(r"\b(zip|rar|7z|iso|html|htm|docm|xlsm|js|vbs|exe)\b", lower))
    if invoice_or_payment_lure or risky_attachment:
        return 0.0

    google_sender = bool(re.search(r"no-reply@accounts\.google\.com|accounts\.google\.com", lower))
    google_notice_hits = len(re.findall(r"new sign-in|if this was you|secure your account|check activity|myaccount\.google\.com|important changes to your google account", lower))

    microsoft_sender = bool(re.search(r"account-security-noreply@accountprotection\.microsoft\.com|accountprotection\.microsoft\.com", lower))
    microsoft_notice_hits = len(re.findall(r"unusual sign-in|verify your identity|recent activity|account security|microsoft account", lower))

    if google_sender and google_notice_hits >= 2:
        return 0.35
    if microsoft_sender and microsoft_notice_hits >= 2:
        return 0.35

    return 0.0


def _url_heuristic_score(url: str) -> float:
    u = str(url or "")
    lower = u.lower()
    score = 0.0

    has_ip = bool(re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", lower))
    keyword_count = len(re.findall(r"login|verify|secure|update|account|password|bank|wallet|confirm", lower))
    has_brand = bool(re.search(r"paypal|bank|wallet|appleid|microsoft|office365|netflix|amazon|facebook|instagram", lower))
    has_credential_lure = bool(re.search(r"login|verify|password|account|secure", lower))
    has_suspicious_host_shape = bool(re.search(r"https?://[^/]*-[^/]*", lower))
    obf_count = len(re.findall(r"[@]|%[0-9a-f]{2}", u, re.IGNORECASE))
    redirect_count = max(len(re.findall(r"https?://", lower)) - 1, 0)
    long_url = len(u) > 75
    suspicious_tld = bool(re.search(r"\.(top|xyz|click|gq|ml|cf|tk)(/|$)", lower))
    subdomain_depth = 0
    host_match = re.search(r"^(?:https?://)?([^/]+)", lower)
    if host_match:
        host = host_match.group(1).split(":")[0]
        subdomain_depth = max(len([p for p in host.split(".") if p]) - 2, 0)

    if has_ip:
        score += 0.2
    if has_ip and has_credential_lure:
        score += 0.2
    if keyword_count > 0:
        score += min(0.3, 0.08 * keyword_count)
    if has_brand and has_credential_lure:
        score += 0.35
    if has_suspicious_host_shape and keyword_count >= 2:
        score += 0.15
    if obf_count > 0:
        score += min(0.2, 0.1 * obf_count)
    if obf_count > 0 and keyword_count > 0:
        score += 0.2
    if redirect_count > 0:
        score += min(0.15, 0.08 * redirect_count)
    if redirect_count > 0 and keyword_count > 0:
        score += 0.1
    if long_url:
        score += 0.1
    if suspicious_tld:
        score += 0.2
    if subdomain_depth >= 3:
        score += 0.1

    return round(min(0.95, score), 4)


def predict_email(text: str) -> dict:
    _ensure_loaded()
    x = email_to_sequence(STATE["email_tokenizer"], text)
    model_score = float(STATE["email_model"].predict(x, verbose=0)[0][0])
    heuristic_score = _email_heuristic_score(text)
    benign_discount = _email_benign_discount(text)
    trusted_discount = _trusted_notice_discount(text)
    adjusted_model_score = max(0.0, model_score - benign_discount - trusted_discount)
    adjusted_heuristic_score = max(0.0, heuristic_score - trusted_discount)
    final_score = max(adjusted_model_score, adjusted_heuristic_score)
    result = _format(final_score)
    result["model_raw_score"] = round(float(model_score), 4)
    result["heuristic_score"] = adjusted_heuristic_score
    result["benign_discount"] = benign_discount
    result["trusted_notice_discount"] = trusted_discount
    return result


def predict_url(url: str) -> dict:
    _ensure_loaded()
    x = extract_url_features(url)
    model_score = float(STATE["url_model"].predict(x, verbose=0)[0][0])
    heuristic_score = _url_heuristic_score(url)
    final_score = max(model_score, heuristic_score)
    result = _format(final_score)
    result["model_raw_score"] = round(float(model_score), 4)
    result["heuristic_score"] = heuristic_score
    return result
