from fastapi import APIRouter, Request

router = APIRouter(prefix="/graphql", tags=["GraphQL"])

@router.post("/introspection")
async def graphql_introspection(request: Request):
    """
    VULNERABILITY: GraphQL Introspection Enabled
    DETAILS: Simulates a GraphQL endpoint that leaves introspection queries enabled.
    THIS ALLOWS: Attackers to dump the entire API schema, exposing hidden queries and mutations.
    """
    body = await request.json()
    query = body.get("query", "")
    if "__schema" in query:
        return {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [{"name": "User"}, {"name": "Admin"}]
                }
            }
        }
    return {"data": {"message": "Invalid query"}}
