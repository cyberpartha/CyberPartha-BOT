from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
class EmergencyStop(RuntimeError):
    pass
def check_stop():
    if (ROOT / "STOP").exists():
        raise EmergencyStop("STOP file is present; request denied.")
