from fastapi import APIRouter

router = APIRouter(prefix="/bola_graphql", tags=["BOLA in GraphQL"])

@router.post("/query")
async def query_user(user_id: int):
    """
    VULNERABILITY: Broken Object Level Authorization (BOLA) in GraphQL
    DETAILS: Allows querying other users' private data by modifying the ID parameter in a GraphQL query.
    """
    return {"data": {"user": {"id": user_id, "private_email": f"user{user_id}@example.com"}}}
