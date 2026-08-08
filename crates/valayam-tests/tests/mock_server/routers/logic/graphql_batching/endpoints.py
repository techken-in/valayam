from fastapi import APIRouter

router = APIRouter(prefix="/graphql_batching", tags=["GraphQL Batching Attack"])

@router.post("/graphql")
async def graphql_batch(queries: list):
    """
    VULNERABILITY: GraphQL Batching Attack
    DETAILS: Accepts arrays of queries to bypass rate limits or perform brute-force attacks in a single request.
    """
    return {"status": "success", "results": [f"Result for query {i}" for i in range(len(queries))]}
