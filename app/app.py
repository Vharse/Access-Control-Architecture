"""
Main Application Entrypoint (Stateless Zero Trust API)
Enforces strict Tenant Context Binding, Path-to-Claim Verification, and RLS integration.
"""

import os
import sys
import uvicorn
import uuid
from typing import Dict, Any
from fastapi import FastAPI, Depends, HTTPException, status, Path
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session
from middleware.auth import require_zero_trust
from database.database import get_db, tenant_context, Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Stateless Zero Trust API",
    docs_url=None,     # Hardened: Disable Swagger UI in zero-trust environments
    redoc_url=None     # Hardened: Disable ReDoc
)

raw_cors = os.getenv(
    "CORS_ORIGINS", 
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173,http://127.0.0.1:7010"
)
cors_origins = [origin.strip() for origin in raw_cors.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-ID"],
    max_age=600
)


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {"status": "healthy", "architecture": "Stateless Zero Trust"}


@app.get("/api/v1/tenants/{tenant_id}/documents", status_code=status.HTTP_200_OK)
def get_tenant_documents(
    tenant_id: str = Path(..., description="Target Tenant Identifier"),
    claims: Dict[str, Any] = Depends(
        require_zero_trust(
            required_role="admin",
            required_clearance=2
        )
    ),
    db: Session = Depends(get_db)
):
    """
    Zero Trust Document Retrieval:
    1. Validates path parameter against authenticated JWT claims (Anti-IDOR/BOLA).
    2. Sets ContextVar and binds PostgreSQL Row-Level Security (RLS) variable.
    3. Queries DB through tenant-isolated session.
    """
    authenticated_tenant = claims.get("tenant_id")

    # 1. Server-Side Zero Trust Validation: Path-to-claim alignment
    if not authenticated_tenant or authenticated_tenant != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Token context does not match target tenant resource."
        )

    # 2. Sanitize and validate UUID format
    try:
        validated_tenant_id = str(uuid.UUID(authenticated_tenant))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid tenant identifier format."
        )

    # 3. ContextVar & PostgreSQL RLS session binding
    tenant_context.set(validated_tenant_id)
    
    try:
        db.execute(
            text("SELECT set_config('app.current_tenant', :tenant, true)"),
            {"tenant": validated_tenant_id}
        )

        raw_results = db.execute(
            text("SELECT id, title, content, tenant_id FROM documents WHERE tenant_id = :tid"),
            {"tid": validated_tenant_id}
        ).fetchall()
        
        documents = [dict(row._mapping) for row in raw_results]
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal database error occurred while fetching tenant resources."
        )

    return {
        "status": "success",
        "tenant_id": validated_tenant_id,
        "caller_sub": claims.get("sub"),
        "documents": documents
    }


if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=7010, reload=True)
