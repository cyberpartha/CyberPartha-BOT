"""
ScopeGuard: fail-closed scope enforcement for every outbound network request.

Design: default-deny; per-program domains; exclusion wins; private-IP block.
"""
from __future__ import annotations
import ipaddress, re, socket
from urllib.parse import urlsplit
from typing import Sequence

_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
        '127.0.0.0/8', '::1/128', 'fc00::/7', '169.254.0.0/16',
    )
]
_ALLOWED_SCHEMES = frozenset({'https'})
_LABEL = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')


def _is_private_ip(hostname: str) -> bool:
    """Return True if hostname resolves to a private/loopback address."""
    try:
        addr = ipaddress.ip_address(socket.gethostbyname(hostname))
        return any(addr in net for net in _PRIVATE_NETS)
    except (socket.gaierror, ValueError, OSError):
        return False  # If DNS fails, let scope check decide


def _valid_hostname(h: str) -> str:
    h = h.strip().lower()
    if not h or len(h) > 253:
        raise ValueError('Invalid hostname length')
    labels = h.rstrip('.').split('.')
    if not all(_LABEL.match(lbl) for lbl in labels if lbl):
        raise ValueError(f'Invalid hostname: {h!r}')
    return h


class ScopeViolation(PermissionError):
    """Raised when a URL is outside the program scope."""


class ScopeGuard:
    """
    Per-program scope enforcement.

    Parameters
    ----------
    allowed_domains : list of hostnames (subdomains auto-included)
    excluded_domains : explicitly excluded hostnames (override allowed)
    lab_mode : allow private IPs for isolated lab environments only
    """

    def __init__(
        self,
        allowed_domains: Sequence[str],
        excluded_domains: Sequence[str] = (),
        lab_mode: bool = False,
    ) -> None:
        if not allowed_domains:
            raise ValueError('At least one allowed domain is required')
        self._allowed = [_valid_hostname(d) for d in allowed_domains]
        self._excluded = [_valid_hostname(d) for d in excluded_domains]
        self._lab_mode = bool(lab_mode)

    def is_allowed_host(self, host: str) -> bool:
        """Return True iff host is in scope and not excluded."""
        try:
            h = _valid_hostname(host)
        except ValueError:
            return False
        if any(h == e or h.endswith('.' + e) for e in self._excluded):
            return False
        return any(h == a or h.endswith('.' + a) for a in self._allowed)

    def check_url(self, url: str) -> None:
        """Assert url is within scope. Raises ScopeViolation on failure."""
        if not isinstance(url, str):
            raise ScopeViolation('URL must be a string')
        try:
            parsed = urlsplit(url)
        except ValueError as exc:
            raise ScopeViolation(f'Unparseable URL: {exc}') from exc

        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise ScopeViolation(
                f'Scheme {parsed.scheme!r} not allowed; only HTTPS permitted'
            )
        if parsed.username or parsed.password:
            raise ScopeViolation('Credentials must not appear in URLs')
        if parsed.fragment:
            raise ScopeViolation('Fragments not permitted in request URLs')

        host = (parsed.hostname or '').lower()
        if not host:
            raise ScopeViolation('URL has no hostname')
        if not self.is_allowed_host(host):
            raise ScopeViolation(f'Host {host!r} is outside configured scope')
        if not self._lab_mode and _is_private_ip(host):
            raise ScopeViolation(
                f'Private/loopback address {host!r} blocked'
            )

    def check_redirect(self, original_url: str, redirect_url: str) -> None:
        """Assert redirect stays in scope and on same host."""
        self.check_url(redirect_url)
        orig_host = (urlsplit(original_url).hostname or '').lower()
        redir_host = (urlsplit(redirect_url).hostname or '').lower()
        if orig_host != redir_host:
            raise ScopeViolation(
                f'Cross-host redirect {orig_host!r} -> {redir_host!r} blocked'
            )
