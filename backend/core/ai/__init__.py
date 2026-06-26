"""IIFVDCAS AI module — multi-provider AI integration for Phases 3–7."""
from .providers import get_provider
from .routes import router

__all__ = ["get_provider", "router"]
