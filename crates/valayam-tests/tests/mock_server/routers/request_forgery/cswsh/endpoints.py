from fastapi import APIRouter, WebSocket

router = APIRouter(prefix="/cswsh", tags=["Cross-Site WebSocket Hijacking"])

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    VULNERABILITY: Cross-Site WebSocket Hijacking (CSWSH)
    DETAILS: Accepts WebSocket connections from any origin without checking the Origin header.
    """
    await websocket.accept()
    await websocket.send_text("Sensitive Data: admin_session_token")
    await websocket.close()
