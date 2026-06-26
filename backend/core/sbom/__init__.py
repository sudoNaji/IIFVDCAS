"""IIFVDCAS Phase 4 — SBOM Package"""

__version__ = "1.0.0"
__phase__ = "Phase 4"
__title__ = "SBOM Generation"

try:
    from .generator import run_sbom_generation as run_generate_sbom
except ImportError:
    run_generate_sbom = None

try:
    from .routes import router as sbom_router
except ImportError:
    sbom_router = None

__all__ = ["run_generate_sbom", "sbom_router"]
