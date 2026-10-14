import time
import requests
from core.scope_guard import is_allowed
def get_profile(access_token, safety, url):
    if not is_allowed(url):
        raise PermissionError("Not allowlisted")
    safety.reserve(url)  # consume BEFORE sending; no retries
    started = time.perf_counter()
    response = requests.get(
        url,
        headers={"Authorization": "Bearer " + access_token,
                 "Accept": "application/json"},
        timeout=15,
        allow_redirects=False,
    )
    elapsed = round((time.perf_counter() - started) * 1000, 1)
    if response.status_code != 200:
        # No body or headers in exception.
        raise RuntimeError("API returned non-200 status")
    try:
        payload = response.json()
    except ValueError:
        raise RuntimeError("Non-JSON response") from None
    return {
        "status": response.status_code,
        "path": "/rest/v1/users/me",
        "elapsed_ms": elapsed,
        "shape": "dict" if isinstance(payload, dict) else "other",
        "response_bytes": len(response.content or b""),
    }
