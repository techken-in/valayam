from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/lfi", tags=["Local File Inclusion"])

@router.get("/download")
async def download_file(file: str):
    """
    VULNERABILITY: Local File Inclusion (LFI)
    DETAILS: Simulates an endpoint vulnerable to path traversal / LFI.
    THIS ALLOWS: Reading sensitive files from the server (e.g., /etc/passwd or C:\Windows\win.ini).
    """
    if ".." in file or "/etc/" in file or "boot.ini" in file or "win.ini" in file:
        return {"status": "success", "file_content": "root:x:0:0:root:/root:/bin/bash\n"}
    
    if file == "report.pdf":
        return {"status": "success", "file_content": "%PDF-1.4..."}
        
    raise HTTPException(status_code=404, detail="File not found")
