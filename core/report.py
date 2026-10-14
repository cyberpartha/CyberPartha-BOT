import json
from datetime import datetime, timezone
from pathlib import Path
def save_report(project_root, result):
    directory = Path(project_root) / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ("baseline-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path
