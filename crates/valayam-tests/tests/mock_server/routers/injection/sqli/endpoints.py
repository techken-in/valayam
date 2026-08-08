from fastapi import APIRouter
import time

router = APIRouter(prefix="/sqli", tags=["SQL Injection"])

@router.get("/users")
async def get_user(id: str):
    """
    VULNERABILITY: SQL Injection (SQLi)
    DETAILS: Simulates an endpoint vulnerable to classic SQL injection via the 'id' parameter.
    THIS ALLOWS: Extracting database contents by injecting SQL syntax (e.g., ' OR 1=1 --).
    """
    if "'" in id or "UNION" in id.upper() or "OR" in id.upper():
        return {"status": "success", "data": [{"id": 1, "username": "admin", "password": "supersecretpassword"}]}
    
    return {"status": "success", "data": [{"id": id, "username": "normal_user"}]}

@router.get("/users/blind")
async def get_user_blind(id: str):
    """
    VULNERABILITY: Blind (Time-Based) SQL Injection
    DETAILS: Simulates an endpoint vulnerable to time-based blind SQL injection via the 'id' parameter.
    THIS ALLOWS: Extracting database contents byte-by-byte by observing response times.
    """
    if "SLEEP(" in id.upper():
        # extract the sleep amount
        try:
            sleep_time = int(id.split("SLEEP(")[1].split(")")[0])
            time.sleep(sleep_time)
        except:
            time.sleep(1)
        
    return {"status": "success", "data": [{"id": id, "username": "normal_user"}]}
