"""Phase 4: localhost-only approval-bound validation. No remote active testing."""
import hashlib
import ipaddress
import json
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from . import core

MAX_BYTES=2048

def _safe_target(url):
    parts=urllib.parse.urlsplit(url)
    if parts.scheme != 'http' or parts.username or parts.password or parts.fragment:
        raise PermissionError('Only plain HTTP local test endpoints permitted')
    if parts.hostname not in ('127.0.0.1', '::1'):
        raise PermissionError('Only literal loopback IP targets permitted')
    if parts.port is None or not (1024 <= parts.port <= 65535):
        raise PermissionError('Explicit nonprivileged local port required')
    if not parts.path.startswith('/') or parts.path.startswith('//') or parts.query:
        raise PermissionError('Path must be absolute; query parameters prohibited')
    if '%' in parts.path or '\\' in parts.path or '..' in parts.path:
        raise PermissionError('Encoded or ambiguous paths prohibited')
    return parts

def _store(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS local_approvals
    (nonce TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, expiry INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS local_audit
    (id INTEGER PRIMARY KEY, created_at INTEGER NOT NULL, target_fingerprint TEXT NOT NULL,
     status TEXT NOT NULL, http_status INTEGER, response_bytes INTEGER)''')
    conn.commit()

def _fingerprint(program,url,method):
    return hashlib.sha256(json.dumps([program,url,method],separators=(',',':')).encode()).hexdigest()

def _ready(program):
    profile=core.load(program)  # Existing, valid profile required; no implicit state creation.
    if profile.get('local_lab_enabled') is not True:
        raise PermissionError('Local lab not explicitly enabled for this profile')
    if (core.BASE/'STOP').exists():
        raise PermissionError('Emergency STOP file present')
    with core.managed_db(program) as conn:
        if core.getmeta(conn,'paused','0')=='1':
            raise PermissionError('Workflow paused')

def enable(program, confirmation):
    """Explicit local-only authorization, separate from bug bounty policy flags."""
    profile=core.load(program)
    if confirmation != 'I OWN THIS LOCAL LAB':
        raise PermissionError('Explicit local-lab ownership confirmation required')
    if (core.BASE/'STOP').exists():
        raise PermissionError('Emergency STOP file present')
    with core.managed_db(program) as conn:
        if core.getmeta(conn,'paused','0')=='1':
            raise PermissionError('Workflow paused')
    profile['local_lab_enabled']=True
    core.save_json(core.profile_path(program),profile)
    return 'Local-lab authorization enabled for '+program

def plan(program,url):
    _ready(program)
    _safe_target(url)
    return {'program':program,'target':url,'method':'GET','max_requests':1,
            'payload':'none','accounts':'none','network':'loopback only',
            'risk':'low-impact local GET; server-side effects still possible',
            'policy':'Local lab only; user must own/control the service',
            'redirects':'disabled','timeout_seconds':3}

def approve(program,url,confirmation):
    p=plan(program,url)
    if confirmation != 'YES':
        raise PermissionError('Explicit YES required')
    nonce=secrets.token_urlsafe(24)
    expiry=int(time.time())+120
    with core.managed_db(program) as conn:
        _store(conn)
        conn.execute('INSERT INTO local_approvals VALUES (?,?,?,0)',
                     (nonce,_fingerprint(program,url,'GET'),expiry))
        conn.commit()
    return {'approval_token':nonce,'expires_in_seconds':120,'plan':p}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

def execute(program,url,token):
    plan(program,url)
    fp=_fingerprint(program,url,'GET')
    with core.managed_db(program) as conn:
        _store(conn)
        # Consume before making any request. Atomic update prevents reuse.
        result=conn.execute('''UPDATE local_approvals SET consumed=1
            WHERE nonce=? AND fingerprint=? AND consumed=0 AND expiry>?''',
            (token,fp,int(time.time())))
        conn.commit()
        if result.rowcount!=1:
            raise PermissionError('Missing, expired, used or mismatched approval')
    # Recheck STOP immediately before network. Cannot interrupt an in-flight request.
    _ready(program)
    opener=urllib.request.build_opener(NoRedirect,urllib.request.ProxyHandler({}))
    req=urllib.request.Request(url,method='GET',headers={'User-Agent':'CyberParthaBOT-LocalLab/4'})
    status='inconclusive'; http_status=None; size=None
    try:
        try:
            response=opener.open(req,timeout=3)
        except urllib.error.HTTPError as e:
            response=e
        with response:
            http_status=response.status
            data=response.read(MAX_BYTES+1)
            size=len(data)
            if size>MAX_BYTES: status='response-limit-exceeded'
            else: status='observed-not-validated'
    except (OSError,ValueError) as e:
        status='transport-error'
    with core.managed_db(program) as conn:
        _store(conn)
        conn.execute('INSERT INTO local_audit(created_at,target_fingerprint,status,http_status,response_bytes) VALUES (?,?,?,?,?)',
                     (int(time.time()),fp,status,http_status,size))
        conn.commit()
    return {'status':status,'http_status':http_status,'bytes_read':size,
            'requests_attempted':1,'finding_confirmed':False,
            'note':'No response body or credentials stored; local lab only'}
