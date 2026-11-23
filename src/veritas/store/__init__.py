"""Evidence and audit storage: the `.veritas` workspace (docs/architecture.md §11)."""

from .audit import GENESIS, AuditChain, VerifyResult, verify
from .blobs import BlobStore, IntegrityError
from .ingest import EXCHANGE_MEDIA_TYPE, SENSOR_MEDIA_TYPE, IngestReport, ingest_gateway_capture
from .workspace import Run, Workspace

__all__ = [
    "EXCHANGE_MEDIA_TYPE",
    "GENESIS",
    "SENSOR_MEDIA_TYPE",
    "AuditChain",
    "BlobStore",
    "IngestReport",
    "IntegrityError",
    "Run",
    "VerifyResult",
    "Workspace",
    "ingest_gateway_capture",
    "verify",
]
