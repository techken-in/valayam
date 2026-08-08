from fastapi import APIRouter

router = APIRouter(prefix="/ldap", tags=["LDAP Injection"])

@router.get("/search")
async def search_ldap(user: str):
    """
    VULNERABILITY: LDAP Injection
    DETAILS: Simulates an endpoint vulnerable to LDAP injection.
    """
    if "*" in user or "|" in user:
        return {"status": "success", "results": ["admin", "user1", "user2"]}
    return {"status": "success", "results": [user]}
