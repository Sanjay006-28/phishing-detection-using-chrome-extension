# Phishing Detection System

TensorFlow/Keras phishing detector for **emails** and **URLs**, served with FastAPI and connected to a Chrome extension.

## Submission Files

- `README.md`
- `requirements.txt`
- `architecture.png`
- `demo_video_link.txt`
- `setup_instructions.md`

## Architecture

System flow is documented in `architecture.png`.

## Project Structure

```text
phishing-detection/
  colab/
    URL_Phishing_Colab.ipynb
    Email_Phishing_Colab.ipynb
  backend/
    main.py
    services/
      preprocess.py
      predict.py
    models/
    tokenizer/
  extension/
    manifest.json
    background.js
    content.js
    popup.html
    popup.js
    styles.css
  requirements.txt
```

## 1) Setup

```bash
cd phishing-detection
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Use one Python environment consistently for training + backend + notebook runs.
In VS Code, select the same interpreter path for this workspace (for example: `.venv\Scripts\python.exe`).

## 2) Train Models

Run notebooks from `phishing-detection/colab/` and use their final save cells.
Artifacts are written to backend folders:

```bash
# URL notebook saves to:
#   ../backend/models/url_model.h5
# Email notebook saves to:
#   ../backend/models/email_model.h5
#   ../backend/tokenizer/email_tokenizer.pkl
```

Artifacts generated:
- `backend/models/email_model.h5`
- `backend/models/url_model.h5`
- `backend/tokenizer/email_tokenizer.pkl`

## 3) Start FastAPI Backend

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Recommended on Windows PowerShell (handles existing process on port 8000):

```powershell
cd phishing-detection
.\scripts\start_backend.ps1
```

Test quickly:

```bash
curl -X POST http://localhost:8000/predict/url -H "Content-Type: application/json" -d '{"url":"http://paypal-secure-login.com"}'
curl -X POST http://localhost:8000/predict/email -H "Content-Type: application/json" -d '{"text":"Your PayPal account is locked. Click here to verify."}'
```

PowerShell smoke test:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/predict/url" -ContentType "application/json" -Body '{"url":"https://paypal-secure-login.com"}'
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/predict/email" -ContentType "application/json" -Body '{"text":"Urgent: verify your bank account now"}'
```

Full assertion-based smoke test (URL + email phishing and safe cases):

```powershell
cd phishing-detection
"c:/Alliance/Chrome Extension final project/.venv/Scripts/python.exe" tests/smoke_test_backend.py
```

## 4) Load Chrome Extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select folder: `phishing-detection/extension`

Behavior:
- Automatic: each visited page URL is checked; page banner appears for safe/phishing.
- Manual: popup allows URL and email text checks.

## Notes

- Backend endpoints used by extension:
  - `http://localhost:8000/predict/url`
  - `http://localhost:8000/predict/email`
- Keep FastAPI running while using extension.
