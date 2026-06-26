"""Phase 6 VEX Engine package"""
try:
    from .routes import router as vex_router
except ImportError:
    vex_router = None

try:
    from .analyzer import run_vex_analysis, VEXResult
except ImportError:
    run_vex_analysis = None
    VEXResult = None

__all__ = ["vex_router", "run_vex_analysis", "VEXResult"]
