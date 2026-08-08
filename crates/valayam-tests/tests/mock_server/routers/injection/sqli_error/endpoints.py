from fastapi import APIRouter

router = APIRouter(prefix="/sqli_error", tags=["Error-Based SQL Injection"])

@router.get("/user")
async def get_user(id: str):
    """VULNERABILITY: Error-based SQLi (GET)"""
    if "'" in id:
        return {"error": "SQL syntax error near '"}
    return {"status": "success", "user": id}

@router.post("/product")
async def create_product(name: str):
    """VULNERABILITY: Error-based SQLi (POST)"""
    if "'" in name:
        return {"error": "Unclosed quotation mark after the character string '"}
    return {"status": "success", "product": name}
