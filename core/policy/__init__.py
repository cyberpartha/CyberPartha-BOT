"""core.policy — Program profile management and policy gating."""
from .profile import ProfileManager, PolicyError
__all__ = ['ProfileManager', 'PolicyError']
