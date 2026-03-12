from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from services.predict import get_runtime_info, load_artifacts, predict_email, predict_url

app = FastAPI(title="Phishing Detection API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000)


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


@app.on_event("startup")
def startup() -> None:
    try:
        load_artifacts()
    except Exception as exc:
        raise RuntimeError(f"Backend startup failed while loading ML artifacts: {exc}") from exc


@app.get("/")
def health() -> dict:
    return {"status": "ok", "service": "phishing-detection"}


@app.get("/health/runtime")
def health_runtime() -> dict:
    return {"status": "ok", **get_runtime_info()}


@app.post("/predict/email")
def predict_email_endpoint(req: EmailRequest) -> dict:
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="text is required")
    return predict_email(req.text)


@app.post("/predict/url")
def predict_url_endpoint(req: UrlRequest) -> dict:
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="url is required")
    return predict_url(req.url)
