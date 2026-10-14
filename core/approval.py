from core.scope_guard import is_allowed
def request_approval(url):
    if not is_allowed(url):
        print("BLOCKED: Target outside allowlist.")
        return False
    print("\nApprove ONE GET to:", url)
    print("OAuth login and token exchange will occur before this GET.")
    try:
        return input("Type YES to authorize this single run: ").strip() == "YES"
    except (EOFError, KeyboardInterrupt):
        return False
