import ipaddress
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

API_KEY = os.getenv('SENTINEL_API_KEY', 'change-me-now')
app = FastAPI(title='SentinelGuard v3')
app.mount('/static', StaticFiles(directory='static'), name='static')
events = deque(maxlen=10000)
incidents = deque(maxlen=1000)
responses = deque(maxlen=2000)
blocked_ips = set()
quarantined_users = set()
BASE_DIR = Path(__file__).resolve().parent
INDEX_HTML_PATH = BASE_DIR / 'static' / 'index.html'
class SecurityEvent(BaseModel):
    timestamp: str | None = None
    source_ip: str = '127.0.0.1'
    username: str = 'unknown'
    action: str = 'unknown'
    status: str = 'unknown'
    endpoint: str = '/agent'
    user_agent: str = 'SentinelGuard-Agent'
    country: str = 'LOCAL'
    host: str = 'unknown'
    source: str = 'agent'
def now():
    return datetime.now(timezone.utc).isoformat()
def ts(v):
    try:
        return datetime.fromisoformat(v.replace('Z', '+00:00')).timestamp()
    except Exception:
        return time.time()
def recent(user=None, host=None, seconds=300):
    cut = time.time() - seconds
    out = []
    for e in reversed(events):
        if ts(e['timestamp']) < cut:
            break
        if user and e['username'] != user:
            continue
        if host and e['host'] != host:
            continue
        out.append(e)
    return out
def private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True
def detect(e):
    f = []
    user = e['username']
    ip = e['source_ip']
    ep = e['endpoint'].lower()
    action = e['action'].lower()
    status = str(e['status']).lower()
    fails = [
        x for x in recent(user=user, host=e['host'])
        if str(x['status']).lower() in {'401', '403', '4625', 'failed', 'failure'}
    ]
    if len(fails) >= 5:
        f.append({
            'rule': 'AUTH-BRUTE-01',
            'title': 'Repeated authentication failures',
            'severity': 'high',
            'confidence': min(.99, .70 + .04 * (len(fails) - 5)),
            'mitre': 'T1110',
            'evidence': f'{len(fails)} authentication failures for {user} on {e["host"]} in 5 minutes.'
        })
    if any(x in ep for x in ('/.env', '/admin', 'wp-admin', 'phpmyadmin', '/actuator', '/debug')):
        f.append({
            'rule': 'WEB-PROBE-02',
            'title': 'Sensitive endpoint probing',
            'severity': 'medium',
            'confidence': .88,
            'mitre': 'T1595',
            'evidence': f'Request targeted sensitive path {ep}.'
        })
    if action in {'password_reset', 'token_refresh', 'session_create'} and status in {'401', '403', 'failed'}:
        f.append({
            'rule': 'SESSION-03',
            'title': 'Authentication/session anomaly',
            'severity': 'medium',
            'confidence': .82,
            'mitre': 'T1078',
            'evidence': f'{action} returned {status}.'
        })
    if action in {'delete_user', 'change_role', 'export_data', 'disable_mfa'} and not private(ip):
        f.append({
            'rule': 'PRIV-04',
            'title': 'External privileged action',
            'severity': 'high',
            'confidence': .86,
            'mitre': 'T1098',
            'evidence': f"Privileged action '{action}' originated from {ip}."
        })
    return f
def decide(f):
    if not f:
        return {'risk': 0, 'decision': 'allow'}
    w = {'low': 25, 'medium': 55, 'high': 82, 'critical': 100}
    risk = max(min(100, w[x['severity']] * x['confidence']) for x in f)
    return {
        'risk': round(risk, 1),
        'decision': 'contain' if risk >= 75 else 'challenge' if risk >= 50 else 'observe'
    }
def auth(k):
    if k != API_KEY:
        raise HTTPException(401, 'Invalid API key')
async def process(e):
    d = e.model_dump()
    d['timestamp'] = d['timestamp'] or now()
    events.append(d)
    f = detect(d)
    dec = decide(f)
    action = dec['decision']
    result = {
        'contain': 'Application-level quarantine recorded.',
        'challenge': 'Step-up verification recommended.',
        'observe': 'Event retained for monitoring.',
        'allow': 'No restriction applied.'
    }[action]
    if action == 'contain':
        blocked_ips.add(d['source_ip'])
        quarantined_users.add(d['username'])
    resp = {
        'timestamp': now(),
        'action': action,
        'target': f"{d['username']} @ {d['host']}",
        'result': result
    }
    responses.appendleft(resp)

    inc = None
    if f:
        inc = {
            'id': f"SG-{int(time.time() * 1000)}",
            'created': now(),
            'host': d['host'],
            'user': d['username'],
            'source_ip': d['source_ip'],
            'risk': dec['risk'],
            'decision': action,
            'summary': f[0]['title'],  # Added to prevent frontend undefined errors
            'findings': f,
            'explanation': (
                f[0]['evidence'] + f" Highest signal confidence: {f[0]['confidence']:.0%}."
            )
        }
        incidents.appendleft(inc)

    return {'findings': f, 'decision': dec, 'incident': inc, 'response': resp}


# API Routes

@app.get('/', response_class=HTMLResponse)
def home():
    with open(INDEX_HTML_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        return HTMLResponse(f.read())


@app.post('/api/agent/events')
async def ingest(event: SecurityEvent, x_sentinel_api_key: str | None = Header(default=None)):
    auth(x_sentinel_api_key)
    return await process(event)


@app.get('/api/agent/health')
async def agent_health(x_sentinel_api_key: str | None = Header(default=None)):
    auth(x_sentinel_api_key)
    return {'status': 'ok', 'time': now(), 'events': len(events)}


@app.get('/api/dashboard')
async def dashboard():
    return {
        'stats': {
            'events': len(events),
            'incidents': len(incidents),
            'contained': len(blocked_ips),
            'critical': sum(1 for i in incidents if i['risk'] >= 75)
        },
        'events': list(events)[-100:][::-1],
        'incidents': list(incidents)[:50],
        'responses': list(responses)[:50]
    }
@app.post('/api/demo')
async def demo():
    # Simulate a suspicious brute-force event stream
    demo_events = [
        SecurityEvent(username="admin", action="login", status="401", endpoint="/admin", source_ip="192.168.1.105", host="WORKSTATION-01"),
        SecurityEvent(username="admin", action="login", status="401", endpoint="/admin", source_ip="192.168.1.105", host="WORKSTATION-01"),
        SecurityEvent(username="admin", action="login", status="401", endpoint="/admin", source_ip="192.168.1.105", host="WORKSTATION-01"),
        SecurityEvent(username="admin", action="login", status="401", endpoint="/admin", source_ip="192.168.1.105", host="WORKSTATION-01"),
        SecurityEvent(username="admin", action="login", status="401", endpoint="/admin", source_ip="192.168.1.105", host="WORKSTATION-01"),
    ]
    
    last_res = None
    for ev in demo_events:
        last_res = await process(ev)
        
    return {"ok": True, "last_result": last_res}

@app.post('/api/reset')
async def reset():
    events.clear()
    incidents.clear()
    responses.clear()
    blocked_ips.clear()
    quarantined_users.clear()
    return {'ok': True}