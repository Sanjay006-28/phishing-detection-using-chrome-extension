import pickle, re
from pathlib import Path
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

ROOT = Path('.').resolve()
ARTIFACT_ROOT = ROOT / 'backend'

def clean_text(t):
    t = str(t).lower()
    t = re.sub(r'[^a-z0-9\s]', ' ', t)
    return re.sub(r'\s+', ' ', t).strip()

def url_features(url):
    import re
    from urllib.parse import urlparse
    u = str(url).strip()
    p = urlparse(u if '://' in u else f'http://{u}')
    host = p.netloc.split(':')[0]
    host_parts = [x for x in host.split('.') if x]
    path_q = f"{p.path}{p.query}"
    is_ip = int(bool(re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host)))
    sub_count = max(len(host_parts) - 2, 0)
    is_https = int(p.scheme.lower() == 'https')
    digit_ratio = (len(re.findall(r'\d', u)) / max(len(u), 1)) if u else 0.0
    special_ratio = (len(re.findall(r'[^a-zA-Z0-9]', u)) / max(len(u), 1)) if u else 0.0
    repeats = [len(m.group(0)) for m in re.finditer(r'(.)\1+', u)]
    cont_rate = (max(repeats) / max(len(u), 1)) if repeats else 0.0
    has_obf = int('%' in u or '@' in u)
    obf_ratio = (len(re.findall(r'[%@]', u)) / max(len(u), 1)) if u else 0.0
    redirects = max(len(re.findall(r'https?://', u)) - 1, 0)
    external_ref = max(path_q.count('http'), 0)
    similarity = max(0.0, 100.0 - special_ratio * 100.0)
    has_ext_form = int('submit' in u and 'http' in path_q)
    has_password = int('password' in u or 'login' in u)
    has_hidden = int('hidden' in u)
    bank = int(any(k in u.lower() for k in ['bank','paypal','card','account']))
    crypto = int(any(k in u.lower() for k in ['crypto','wallet','btc','eth']))
    v = [float(len(u)), float(is_ip), float(sub_count), float(is_https), float(digit_ratio), float(special_ratio), float(cont_rate), float(has_obf), float(obf_ratio), float(redirects), float(external_ref), float(similarity), 0.0, 0.0, float(has_ext_form), float(has_password), float(has_hidden), float(bank), float(crypto)]
    return np.array([v], dtype='float32')

email_model = load_model(ARTIFACT_ROOT / 'models' / 'email_model.h5')
url_model = load_model(ARTIFACT_ROOT / 'models' / 'url_model.h5')
with open(ARTIFACT_ROOT / 'tokenizer' / 'email_tokenizer.pkl', 'rb') as f:
    tok = pickle.load(f)

sample_email = 'Your PayPal account is locked. Click here to verify immediately.'
x_email = pad_sequences(tok.texts_to_sequences([clean_text(sample_email)]), maxlen=120, padding='post', truncating='post')
email_score = float(email_model.predict(x_email, verbose=0)[0][0])

sample_url = 'http://paypal-secure-login.com'
x_url = url_features(sample_url)
url_score = float(url_model.predict(x_url, verbose=0)[0][0])

print('EMAIL INPUT:', sample_email)
print('EMAIL OUTPUT:', {'prediction': 'phishing' if email_score >= 0.5 else 'safe', 'confidence': round(email_score if email_score >= 0.5 else 1-email_score, 4), 'raw_score': round(email_score, 4)})
print('URL INPUT:', sample_url)
print('URL OUTPUT:', {'prediction': 'phishing' if url_score >= 0.5 else 'safe', 'confidence': round(url_score if url_score >= 0.5 else 1-url_score, 4), 'raw_score': round(url_score, 4)})
