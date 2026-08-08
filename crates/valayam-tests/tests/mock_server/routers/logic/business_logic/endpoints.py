from fastapi import APIRouter

router = APIRouter(prefix="/business_logic", tags=["Business Logic Flaw"])

@router.post("/checkout")
async def checkout(item_id: int, quantity: int):
    """
    VULNERABILITY: Business Logic Flaw
    DETAILS: Allows negative quantities to reduce the total cost of an order.
    """
    price = 100
    total = price * quantity
    return {"status": "success", "message": f"Checked out {quantity} items. Total charged: ${total}"}
