import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000"


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def post_json(path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_json(path: str) -> dict:
    req = urllib.request.Request(f"{BASE}{path}", method="GET")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    try:
        health = get_json("/")
        runtime = get_json("/health/runtime")
        url_phish = post_json("/predict/url", {"url": "https://paypal-secure-login.com"})
        url_phish_ip = post_json("/predict/url", {"url": "http://192.168.1.200/login/verify-account"})
        url_phish_encoded = post_json("/predict/url", {"url": "http://example.com/%40login/verify?next=http://evil.com"})
        url_safe = post_json("/predict/url", {"url": "https://www.google.com"})
        url_safe_dev = post_json("/predict/url", {"url": "https://github.com/features"})

        email_phish = post_json("/predict/email", {"text": "Urgent: verify your account immediately."})
        email_phish_suspension = post_json(
            "/predict/email",
            {"text": "Your university account will be suspended unless you revalidate now at htxps://portal-verify.com."},
        )
        email_phish_invoice = post_json(
            "/predict/email",
            {
                "text": (
                    "Dear Customer, attached invoice document for your recent transaction. "
                    "Please review and proceed with payment. Attachment: Invoice_Document_2026.zip"
                )
            },
        )
        email_safe_google_notice = post_json(
            "/predict/email",
            {
                "text": (
                    "Google <no-reply@accounts.google.com> A new sign-in on Windows. "
                    "If this was you, you don't need to do anything. If not, secure your account. "
                    "Check activity at https://myaccount.google.com/notifications"
                )
            },
        )
        email_safe = post_json(
            "/predict/email",
            {"text": "Hi team, sharing meeting notes from today. No action required; thank you."},
        )

        expect(health.get("status") == "ok", "GET / did not return status=ok")
        expect(runtime.get("loaded") is True, "Runtime artifacts are not loaded")
        expect("artifacts" in runtime and isinstance(runtime["artifacts"], dict), "Runtime artifacts metadata missing")
        expect(url_phish.get("prediction") == "phishing", "Suspicious URL should be classified as phishing")
        expect(url_phish_ip.get("prediction") == "phishing", "IP + credential-lure URL should be classified as phishing")
        expect(url_phish_encoded.get("prediction") == "phishing", "Obfuscated URL should be classified as phishing")
        expect(url_safe.get("prediction") == "safe", "Known safe URL should be classified as safe")
        expect(url_safe_dev.get("prediction") == "safe", "Known safe developer URL should be classified as safe")
        expect(email_phish.get("prediction") == "phishing", "Suspicious email should be classified as phishing")
        expect(email_phish_suspension.get("prediction") == "phishing", "Suspension-threat email should be classified as phishing")
        expect(email_phish_invoice.get("prediction") == "phishing", "Invoice attachment lure email should be classified as phishing")
        expect(email_safe_google_notice.get("prediction") == "safe", "Genuine Google account-security notice should be classified as safe")
        expect(email_safe.get("prediction") == "safe", "Benign email should be classified as safe")

        print("[PASS] GET / ->", health)
        print("[PASS] GET /health/runtime ->", runtime)
        print("[PASS] POST /predict/url (phishing sample) ->", url_phish)
        print("[PASS] POST /predict/url (ip phishing sample) ->", url_phish_ip)
        print("[PASS] POST /predict/url (encoded phishing sample) ->", url_phish_encoded)
        print("[PASS] POST /predict/url (safe sample) ->", url_safe)
        print("[PASS] POST /predict/url (safe dev sample) ->", url_safe_dev)
        print("[PASS] POST /predict/email (phishing sample) ->", email_phish)
        print("[PASS] POST /predict/email (suspension sample) ->", email_phish_suspension)
        print("[PASS] POST /predict/email (invoice lure sample) ->", email_phish_invoice)
        print("[PASS] POST /predict/email (google notice sample) ->", email_safe_google_notice)
        print("[PASS] POST /predict/email (safe sample) ->", email_safe)
        return 0
    except AssertionError as e:
        print(f"[FAIL] Assertion: {e}")
        return 1
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"[FAIL] HTTP {e.code}: {body}")
        return 1
    except Exception as e:
        print(f"[FAIL] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
