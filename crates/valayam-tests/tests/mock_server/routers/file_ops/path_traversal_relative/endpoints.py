from fastapi import APIRouter

router = APIRouter(prefix="/path_traversal_relative", tags=["Relative Path Traversal"])

@router.get("/fetch")
async def fetch_file(path: str):
    """VULNERABILITY: Relative Path Traversal via URL Encoding"""
    if "%2e%2e%2f" in path.lower() or "../" in path:
        return {"status": "success", "content": "root:x:0:0"}
    return {"status": "success", "content": "normal content"}

@router.get("/download")
async def download_file(path: str):
    """VULNERABILITY: Relative Path Traversal via Double URL Encoding"""
    if "%252e%252e%252f" in path.lower():
        return {"status": "success", "content": "system_config"}
    return {"status": "success", "content": "normal content"}
