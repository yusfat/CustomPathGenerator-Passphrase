#===== custompath/__init__.py =====

# custompath/__init__.py

from .generator import make_path
from .crypto import make_random_salt, make_system_salt, make_password

__all__ = ["make_path", "make_random_salt", "make_system_salt", "make_password"]