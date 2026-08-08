from fastapi import APIRouter, UploadFile, File

router = APIRouter(prefix="/zip_slip", tags=["Zip Slip"])

@router.post("/extract")
async def extract_zip(file: UploadFile = File(...)):
    """
    VULNERABILITY: Zip Slip (Directory Traversal via Archive)
    DETAILS: Simulates extracting a ZIP file without validating the extracted paths.
    """
    if "../" in file.filename:
        return {"status": "success", "message": f"Extracted to ../../../{file.filename}"}
    return {"status": "success", "message": "Extracted safely"}
