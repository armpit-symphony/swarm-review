"""SwarmReview CLI — re-exported from swarm_review_cli for backward compatibility."""
from swarm_review_cli import (
    build_parser,
    main,
    run_doctor,
    run_review,
    run_scan,
)
from swarm_review_cli import (
    _consent_file_path as _consent_file_path,
    _enforce_deep_consent as _enforce_deep_consent,
    _prepare_schema_findings as _prepare_schema_findings,
)

__all__ = [
    "build_parser",
    "main",
    "run_doctor",
    "run_review",
    "run_scan",
    "_consent_file_path",
    "_enforce_deep_consent",
    "_prepare_schema_findings",
]
