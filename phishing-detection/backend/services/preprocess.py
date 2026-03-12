import re
from urllib.parse import urlparse

import numpy as np
from tensorflow.keras.preprocessing.sequence import pad_sequences

MAX_EMAIL_LEN = 120
URL_FEATURE_COLUMNS = [
    "URLLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "IsHTTPS",
    "DegitRatioInURL",
    "SpacialCharRatioInURL",
    "CharContinuationRate",
    "HasObfuscation",
    "ObfuscationRatio",
    "NoOfURLRedirect",
    "NoOfExternalRef",
    "URLSimilarityIndex",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasExternalFormSubmit",
    "HasPasswordField",
    "HasHiddenFields",
    "Bank",
    "Crypto",
]


def clean_text(text: str) -> str:
    text = str(text).lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def email_to_sequence(tokenizer, text: str) -> np.ndarray:
    seq = tokenizer.texts_to_sequences([clean_text(text)])
    return pad_sequences(seq, maxlen=MAX_EMAIL_LEN, padding="post", truncating="post")


def _ratio(pattern: str, s: str) -> float:
    return (len(re.findall(pattern, s)) / max(len(s), 1)) if s else 0.0


def extract_url_features(url: str) -> np.ndarray:
    u = str(url).strip()
    parsed = urlparse(u if "://" in u else f"http://{u}")
    host = parsed.netloc.split(":")[0]
    host_parts = [p for p in host.split(".") if p]
    path_q = f"{parsed.path}{parsed.query}"

    is_ip = int(bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)))
    sub_count = max(len(host_parts) - 2, 0)
    is_https = int(parsed.scheme.lower() == "https")
    digit_ratio = _ratio(r"\d", u)
    special_ratio = _ratio(r"[^a-zA-Z0-9]", u)
    repeats = [len(m.group(0)) for m in re.finditer(r"(.)\1+", u)]
    cont_rate = (max(repeats) / max(len(u), 1)) if repeats else 0.0
    has_obf = int("%" in u or "@" in u)
    obf_ratio = _ratio(r"[%@]", u)
    redirects = max(len(re.findall(r"https?://", u)) - 1, 0)
    external_ref = max(path_q.count("http"), 0)
    similarity = max(0.0, 100.0 - special_ratio * 100.0)
    has_ext_form = int("submit" in u and "http" in path_q)
    has_password = int("password" in u or "login" in u)
    has_hidden = int("hidden" in u)
    bank = int(any(k in u.lower() for k in ["bank", "paypal", "card", "account"]))
    crypto = int(any(k in u.lower() for k in ["crypto", "wallet", "btc", "eth"]))

    vec = [
        float(len(u)), float(is_ip), float(sub_count), float(is_https), float(digit_ratio),
        float(special_ratio), float(cont_rate), float(has_obf), float(obf_ratio), float(redirects),
        float(external_ref), float(similarity), 0.0, 0.0, float(has_ext_form), float(has_password),
        float(has_hidden), float(bank), float(crypto),
    ]
    return np.array([vec], dtype="float32")
