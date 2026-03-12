# Setup Instructions

## 1. Clone and enter project

```powershell
git clone <your-repo-url>
cd phishing-detection
```

## 2. Create and activate virtual environment (Windows)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## 3. Install dependencies

```powershell
pip install -r requirements.txt
```

## 4. Start backend API

```powershell
.\scripts\start_backend.ps1
```

The API runs at:
- http://127.0.0.1:8000

## 5. Load Chrome extension

1. Open `chrome://extensions`
2. Turn on **Developer mode**
3. Click **Load unpacked**
4. Select the `extension` folder

## 6. Verify backend endpoints (optional)

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/predict/url" -ContentType "application/json" -Body '{"url":"http://paypal-secure-login.com"}'
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/predict/email" -ContentType "application/json" -Body '{"text":"Urgent: verify your account now."}'
```
