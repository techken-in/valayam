from fastapi import APIRouter

router = APIRouter(prefix="/graphql_introspection", tags=["GraphQL Introspection"])

@router.post("/query")
async def introspection(query: str):
    """
    VULNERABILITY: GraphQL Introspection Enabled
    DETAILS: Exposes the entire GraphQL schema to unauthenticated users via introspection queries.
    """
    if "__schema" in query:
        return {"data": {"__schema": {"types": [{"name": "User", "fields": [{"name": "password"}]}]}}}
    return {"data": {}}
