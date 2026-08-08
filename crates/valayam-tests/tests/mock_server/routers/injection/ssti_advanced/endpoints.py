from fastapi import APIRouter

router = APIRouter(prefix="/ssti_advanced", tags=["Advanced SSTI"])

@router.post("/render_jinja")
async def render_jinja(template: str):
    """VULNERABILITY: Advanced SSTI bypassing simple filters in Jinja"""
    if "request.application.__globals__" in template:
        return {"status": "success", "rendered": "RCE Executed via Jinja globals"}
    return {"status": "success", "rendered": template}

@router.post("/render_twig")
async def render_twig(template: str):
    """VULNERABILITY: Advanced SSTI via Twig context manipulation"""
    if "_self.env.registerUndefinedFilterCallback" in template:
        return {"status": "success", "rendered": "RCE Executed via Twig callbacks"}
    return {"status": "success", "rendered": template}
