from fastapi import APIRouter, UploadFile, File

router = APIRouter(prefix="/file_upload_advanced", tags=["Advanced File Upload"])

@router.post("/avatar")
async def upload_avatar(file: UploadFile = File(...)):
    """VULNERABILITY: Allows executable uploads like .php or .py"""
    if file.filename.endswith(".php"):
        return {"status": "success", "message": "Uploaded PHP shell"}
    return {"status": "success", "filename": file.filename}

@router.post("/document")
async def upload_document(file: UploadFile = File(...)):
    """VULNERABILITY: Allows XSS via SVG or HTML uploads"""
    if file.filename.endswith(".html") or file.filename.endswith(".svg"):
        return {"status": "success", "message": "Uploaded XSS vector"}
    return {"status": "success", "filename": file.filename}
