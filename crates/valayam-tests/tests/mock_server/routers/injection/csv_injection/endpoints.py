from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

router = APIRouter(prefix="/csv_injection", tags=["CSV Injection"])

@router.get("/export")
async def export_csv(name: str):
    """
    VULNERABILITY: CSV / Formula Injection
    DETAILS: Directly places user input into a CSV format without escaping.
    """
    csv_content = f"id,name,role\n1,{name},user\n"
    return PlainTextResponse(content=csv_content, media_type="text/csv")
