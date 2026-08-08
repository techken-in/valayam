from fastapi import APIRouter, UploadFile, File

router = APIRouter(prefix="/upload", tags=["Unrestricted File Upload"])

@router.post("/file")
async def upload_file(file: UploadFile = File(...)):
    """
    VULNERABILITY: Unrestricted File Upload
    DETAILS: Accepts any file extension without validation.
    """
    return {"status": "success", "filename": file.filename, "content_type": file.content_type}
