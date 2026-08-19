"""SecScanMonitor firm platform.

The governed security-firm control plane. Canonical architecture:
docs/SECSCANMONITOR_FIRM_PLATFORM_ARCHITECTURE_V1.md. Layer law: dependencies
point inward; domain/ is pure (no FastAPI/Temporal/SQLAlchemy/Docker/Hermes/
provider-SDK imports). Enforced by tests/test_platform/test_architecture.py.
"""

__version__ = "0.1.0"
