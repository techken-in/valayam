from fastapi import APIRouter

router = APIRouter(prefix="/path_traversal_absolute", tags=["Absolute Path Traversal"])

@router.get("/read")
async def read_file(filepath: str):
    """
    VULNERABILITY: Absolute Path Traversal
    DETAILS: Simulates reading an absolute file path directly without restricting to a specific directory.
    """
    if filepath.startswith("/etc/") or filepath.startswith("C:\\"):
        return {"status": "success", "content": "root:x:0:0:root:/root:/bin/bash"}
    return {"status": "success", "content": "normal file content"}
