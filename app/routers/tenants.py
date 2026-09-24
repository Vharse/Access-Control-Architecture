
from fastapi import APIRouter, Depends
from security.dependencies import require_zero_trust

router = APIRouter(prefix="/api/v1/tenants", tags=["Tenants"])

@router.get("/{tenant_id}/documents")
async def get_tenant_documents(
    tenant_id: str,
    claims: dict = Depends(require_zero_trust(required_role="admin", required_clearance=2))
):
    # RLS is already active via the transaction, and Anti-BOLA is enforced by the dependency.
    return {
        "status": "success",
        "tenant_id": tenant_id,
        "user": claims.get("sub"),
        "documents": [] # Query results from your database model here
    }
