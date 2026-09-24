"""
Zero Trust Authentication & ABAC Dependency with Structured Audit Logging
"""
import uuid
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from security.jwt_validator import validate_jwt
from security.audit import log_security_event
from database.database import tenant_context

security = HTTPBearer()

async def audit_enforcement_gate(
    request: Request, 
    claims: dict, 
    check_type: str, 
    reason: str, 
    status_code: int
):
    """Helper to log security violations and raise HTTP exceptions."""
    client_ip = request.client.host if request.client else "unknown"
    user_id = claims.get("sub", "unknown")
    tenant_id = claims.get("tenant_id", "unknown")
    
    log_security_event(
        event_type=check_type,
        status_code=status_code,
        reason=reason,
        client_ip=client_ip,
        user_id=user_id,
        tenant_id=tenant_id,
        extra_metadata={"path": request.url.path, "method": request.method}
    )
    
    raise HTTPException(status_code=status_code, detail=reason)


def require_zero_trust(
    required_role: Optional[str] = None, 
    required_clearance: int = 0
):
    async def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials = Security(security)
    ) -> Dict[str, Any]:
        token = credentials.credentials
        
        # 1. Stateless JWT Verification (Cryptographic signature, exp, iat, alg whitelist)
        claims = validate_jwt(token)
        
        raw_token_tenant = claims.get("tenant_id")
        if not raw_token_tenant:
            await audit_enforcement_gate(
                request, claims, 
                check_type="MISSING_TENANT_CLAIM",
                reason="Unauthorized: Token missing 'tenant_id' claim.",
                status_code=status.HTTP_401_UNAUTHORIZED
            )
            
        # Zero-Trust UUID Normalization & Validation for Token Tenant
        try:
            token_tenant = str(uuid.UUID(str(raw_token_tenant)))
        except (ValueError, TypeError, AttributeError):
            await audit_enforcement_gate(
                request, claims,
                check_type="INVALID_TENANT_FORMAT",
                reason="Unauthorized: Token 'tenant_id' claim is not a valid UUID format.",
                status_code=status.HTTP_401_UNAUTHORIZED
            )
            
        # 2. Vector 2: Anti-BOLA / IDOR Verification with UUID validation
        raw_path_tenant = request.path_params.get("tenant_id")
        if raw_path_tenant:
            try:
                path_tenant = str(uuid.UUID(str(raw_path_tenant)))
            except (ValueError, TypeError, AttributeError):
                await audit_enforcement_gate(
                    request, claims,
                    check_type="INVALID_PATH_TENANT_FORMAT",
                    reason="Bad Request: Target path tenant identifier is not a valid UUID format.",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            
            if path_tenant != token_tenant:
                await audit_enforcement_gate(
                    request, claims,
                    check_type="ANTI_BOLA_VIOLATION",
                    reason=f"Forbidden: Token tenant '{token_tenant}' does not match target path tenant '{path_tenant}'.",
                    status_code=status.HTTP_403_FORBIDDEN
                )

        # 3. Vector 3: ABAC & RBAC Attribute Gate Evaluation
        user_role = claims.get("role")
        user_clearance = claims.get("clearance", 0)
        
        if required_role and user_role != required_role:
            await audit_enforcement_gate(
                request, claims,
                check_type="RBAC_ROLE_VIOLATION",
                reason=f"Forbidden: Role '{user_role}' does not satisfy required role '{required_role}'.",
                status_code=status.HTTP_403_FORBIDDEN
            )
            
        if user_clearance < required_clearance:
            await audit_enforcement_gate(
                request, claims,
                check_type="ABAC_CLEARANCE_VIOLATION",
                reason=f"Forbidden: Clearance level {user_clearance} is below required level {required_clearance}.",
                status_code=status.HTTP_403_FORBIDDEN
            )

        # 4. ContextVar Binding for PostgreSQL RLS Isolation
        # Setting context for the request session
        token_ctx = tenant_context.set(token_tenant)
        request.state.tenant_id = token_tenant
        request.state.user = claims
        
        try:
            return claims
        finally:
            # Note: While FastAPI cleans up request states, explicit context tracking
            # can be tied here if custom async task transitions occur.
            pass

    return dependency
