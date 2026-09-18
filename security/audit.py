"""
Structured Security Audit Logger
Emits JSON-formatted security telemetry for SIEM and log aggregation.
"""
import logging
import json
import sys
from datetime import datetime, timezone
from typing import Optional, Dict, Any

logger = logging.getLogger("zero_trust.audit")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    logger.addHandler(handler)

def log_security_event(
    event_type: str,
    status_code: int,
    reason: str,
    client_ip: Optional[str] = None,
    user_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None
) -> None:
    """
    Logs a structured JSON security violation or audit event.
    """
    audit_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_category": "ZERO_TRUST_AUDIT",
        "event_type": event_type,
        "status_code": status_code,
        "client_ip": client_ip or "unknown",
        "user_id": user_id or "anonymous",
        "tenant_id": tenant_id or "unauthenticated",
        "reason": reason,
        "metadata": extra_metadata or {}
    }
    
    logger.warning(json.dumps(audit_record))
