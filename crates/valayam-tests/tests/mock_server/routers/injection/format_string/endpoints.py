from fastapi import APIRouter

router = APIRouter(prefix="/format_string", tags=["Format String Injection"])

class Config:
    def __init__(self):
        self.secret = "SUPER_SECRET_KEY"

config = Config()

@router.get("/greet")
async def greet(name: str):
    """
    VULNERABILITY: Python Format String Injection
    DETAILS: Unsafely uses str.format() with user input, allowing access to globals and object attributes.
    """
    # Attacker payload: {config.secret}
    template = "Hello, " + name + "!"
    try:
        greeting = template.format(config=config)
    except:
        greeting = "Error"
    return {"message": greeting}
