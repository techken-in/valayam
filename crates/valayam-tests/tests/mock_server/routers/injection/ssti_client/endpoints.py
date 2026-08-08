from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/ssti_client", tags=["Client-Side Template Injection"])

@router.get("/render")
async def client_template(name: str):
    """
    VULNERABILITY: Client-Side Template Injection (CSTI)
    DETAILS: Simulates reflecting user input into an AngularJS/Vue context without sanitization.
    """
    html = f"<html><script src='https://ajax.googleapis.com/ajax/libs/angularjs/1.5.6/angular.min.js'></script><body ng-app>Welcome, {name}</body></html>"
    return HTMLResponse(content=html)
