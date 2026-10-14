"""Phase 3: offline endpoint inventory + explainable hypotheses, NO target traffic or LLM API."""
import json, re, hashlib
from urllib.parse import urlsplit
from . import core

ALLOWED_METHODS = {'GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'}
SENSITIVE = re.compile(r'(?i)(token|secret|password|key|cookie|authorization|session|jwt|email|phone|credential|signature)')
RULES = (
    ('access-control', {'id','user_id','account_id','owner_id','document_id','order_id','resource_id'}, 'Review object-level authorization with two owned resources', 3),
    ('authentication', {'login','logout','refresh','mfa','reset','session'}, 'Review own-account authentication and session lifecycle', 3),
    ('injection', {'search','query','filter','sort','template'}, 'Review input handling with non-destructive validation', 2),
    ('ssrf', {'webhook','callback','redirect','url','fetch','import'}, 'Review server-side URL handling without internal probes', 2),
    ('business-logic', {'checkout','coupon','cart','transfer','purchase'}, 'Review owned-workflow state transitions', 2),
    ('misconfiguration', {'cors','origin','headers'}, 'Review security configuration using permitted observation', 1),
)

def normalize_path(path):
    if not isinstance(path,str) or not path.startswith('/') or len(path)>512:
        raise ValueError('Only relative URL paths up to 512 characters accepted')
    if any(x in path for x in ('?','#','\\','@')) or any(ord(x)<32 for x in path):
        raise ValueError('No query values, fragments or control characters in path')
    parts=[]
    for segment in path.split('/'):
        if segment in ('.','..') or '%' in segment: raise ValueError('Encoded/relative path not accepted')
        if re.fullmatch(r'[0-9]{1,18}',segment) or re.fullmatch(r'[a-fA-F0-9]{8}-[a-fA-F0-9-]{20,}',segment):
            segment='{id}'
        if not re.fullmatch(r'[A-Za-z0-9_{}.-]*',segment): raise ValueError('Unsupported path characters')
        if SENSITIVE.search(segment):
            # Avoid storing accidental secrets in path segments.
            segment='{redacted}'
        parts.append(segment)
    return '/'.join(parts)

def normalize_endpoint(record, profile):
    if not isinstance(record,dict): raise ValueError('Endpoint must be an object')
    # Only a strict, non-sensitive schema; all other fields rejected to avoid secrets/bodies.
    if set(record)-{'host','method','path','parameters','auth_required','source'}:
        raise ValueError('Unexpected fields: do not provide headers, bodies, tokens or query values')
    host=core.valid_domain(record.get('host',''))
    if not core.in_scope(host,profile): raise PermissionError('Host out of configured scope')
    method=record.get('method','GET')
    if method not in ALLOWED_METHODS: raise ValueError('Unsupported method')
    path=normalize_path(record.get('path',''))
    parameters=record.get('parameters',[])
    if not isinstance(parameters,list) or len(parameters)>32: raise ValueError('Parameter names list required (max 32)')
    cleaned=[]
    for item in parameters:
        if not isinstance(item,str) or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_]{0,39}',item):
            raise ValueError('Parameter names only; no values')
        if SENSITIVE.search(item):
            cleaned.append('{sensitive_parameter}')
        else: cleaned.append(item.lower())
    auth=record.get('auth_required','unknown')
    if auth not in (True,False,'unknown'): raise ValueError('Invalid auth_required')
    source=record.get('source','manual')
    if source not in ('manual','har','openapi','archive','ct','other'):
        raise ValueError('Unsupported source label')
    return {'host':host,'method':method,'path':path,'parameters':sorted(set(cleaned)),
            'auth_required':auth,'source':source}

def reason(endpoint):
    tokens=set(re.findall(r'[a-z]+(?:_[a-z]+)*',endpoint['path'].lower()))
    tokens.update(endpoint['parameters'])
    # Split path segment words only for matching; don't assume vulnerability.
    if '{id}' in endpoint['path']: tokens.add('id')
    hypotheses=[]
    for category,markers,title,budget in RULES:
        matched=sorted(tokens & markers)
        if not matched:continue
        score=min(90,25+15*len(matched)+(10 if endpoint['auth_required'] is True and category=='access-control' else 0))
        hypotheses.append({'category':category,'title':title,'priority_score':score,
                           'evidence_labels':matched,'max_requests_proposed':budget,
                           'status':'hypothesis_not_validated'})
    return sorted(hypotheses,key=lambda h:(-h['priority_score'],h['category']))

def analyze_file(name,filename):
    profile=core.load(name)
    if not profile['policy_reviewed'] or not profile['ai_allowed']:
        raise PermissionError('Human-reviewed policy and AI permission required for automated analysis')
    with core.managed_db(name) as conn:
        if core.getmeta(conn,'paused','0')=='1': raise PermissionError('Program is paused')
    from pathlib import Path
    p=Path(filename)
    if p.stat().st_size>200_000: raise ValueError('Input too large (200KB maximum)')
    records=json.loads(p.read_text(encoding='utf-8'))
    if not isinstance(records,list) or len(records)>200: raise ValueError('Expected JSON list of <=200 endpoints')
    # Atomic validation: reject whole file if any endpoint invalid/out of scope.
    normalized=[normalize_endpoint(r,profile) for r in records]
    unique={json.dumps(r,sort_keys=True):r for r in normalized}
    output=[]
    for ep in unique.values():
        output.append({'endpoint':ep,'hypotheses':reason(ep)})
    output.sort(key=lambda x:(x['endpoint']['host'],x['endpoint']['path'],x['endpoint']['method']))
    # Do not persist raw input, headers, cookies, response bodies, or query values.
    path=core.REPORTS/(core.valid_name(name)+'-phase3-analysis.json')
    core.save_json(path,{'program':name,'source':'operator-provided sanitized metadata',
                         'network_requests':0,'ai_model_calls':0,
                         'note':'Heuristic prioritization, NOT confirmed vulnerabilities or AI model inference.',
                         'results':output})
    return path,len(output),sum(len(x['hypotheses']) for x in output)
