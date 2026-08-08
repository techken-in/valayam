from fastapi import APIRouter, Request

router = APIRouter(prefix="/method_tampering", tags=["HTTP Method Tampering"])

@router.route("/admin", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def admin_action(request: Request):
    """
    VULNERABILITY: HTTP Method Tampering
    DETAILS: Access control is only enforced on GET and POST, allowing bypass via HEAD or arbitrary methods.
    """
    if request.method in ["GET", "POST"]:
        return {"status": "error", "message": "Access Denied"}
    # Bypass logic for other methods
    return {"status": "success", "message": f"Action performed via {request.method}"}
