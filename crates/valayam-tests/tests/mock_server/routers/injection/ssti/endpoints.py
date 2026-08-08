from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/ssti", tags=["Server-Side Template Injection"])

@router.get("/render", response_class=HTMLResponse)
async def render_template(name: str = "Guest"):
    """
    VULNERABILITY: Server-Side Template Injection (SSTI)
    DETAILS: Simulates an endpoint vulnerable to SSTI by evaluating user input as a template.
    THIS ALLOWS: Remote Code Execution (RCE) by injecting template engine payloads.
    """
    if "{{" in name and "}}" in name:
        try:
            expr = name.replace("{{", "").replace("}}", "")
            # Simulating dangerous evaluation
            result = eval(expr)
            return f"<h1>Hello, {result}!</h1>"
        except:
            return f"<h1>Hello, {name}!</h1>"

    return f"<h1>Hello, {name}!</h1>"
