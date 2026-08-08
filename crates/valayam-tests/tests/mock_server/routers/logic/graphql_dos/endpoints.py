from fastapi import APIRouter

router = APIRouter(prefix="/graphql_dos", tags=["GraphQL DoS"])

@router.post("/query")
async def execute_query(query: dict):
    """
    VULNERABILITY: GraphQL Query Depth / DoS
    DETAILS: Simulates accepting deeply nested GraphQL queries leading to DoS.
    """
    # In a real app, query depth is not checked
    return {"status": "success", "message": "Query executed"}
