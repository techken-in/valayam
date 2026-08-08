from fastapi import APIRouter
import re

router = APIRouter(prefix="/redos", tags=["Regular Expression DoS"])

@router.post("/validate_email")
async def validate_email(email: str):
    """
    VULNERABILITY: Regular Expression Denial of Service (ReDoS)
    DETAILS: Evaluates user input against a poorly crafted, catastrophic backtracking regex.
    """
    # Vulnerable regex pattern
    pattern = "^([a-zA-Z0-9]+)+$"
    try:
        if re.match(pattern, email):
            return {"status": "success"}
    except:
        pass
    return {"status": "error"}
