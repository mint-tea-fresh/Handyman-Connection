from __future__ import annotations

from dotenv import load_dotenv

from jobber_mcp.app import create_app
from jobber_mcp.config import Settings


def create_application():
    """Create the production ASGI application from environment settings."""
    load_dotenv()
    return create_app(Settings.from_env())
