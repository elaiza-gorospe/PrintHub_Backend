# Stock Deduction Feature - Testing Guide

## Overview

Product stock is now automatically deducted when orders are created and restored when orders are cancelled.

## Implementation Summary

### Changes Made to `/api/orders` POST endpoint (Line ~744)

**✅ Stock Validation**

- Before order creation, the system checks if each product has sufficient stock
- If any product has insufficient stock, the order is rejected with a detailed error message including:
  - Product name
  - Product ID
  - Available stock
  - Requested quantity
- Example error response:

```json
{
  "message": "Insufficient stock for Business Cards. Available: 50, Requested: 100",
  "productId": 1,
  "productName": "Business Cards",
  "available": 50,
  "requested": 100
}
```

**✅ Stock Deduction**

- After order is successfully created, stock is automatically decremented
- Uses Prisma transaction to ensure atomicity (all-or-nothing)
- Each OrderItem quantity is subtracted from the corresponding Product.stock

**✅ Removed Duplicate Endpoint**

- Removed the second POST `/api/orders` endpoint (was at line ~1473) that was overriding the first one
- Consolidated all order creation logic into one endpoint

### Changes Made to DELETE Order Endpoint (Line ~1620)

**✅ Stock Restoration**

- When an order is deleted (soft-deleted), stock is restored for all items in that order
- Uses transaction to ensure atomicity
- For each OrderItem, the quantity is added back to Product.stock

### Changes Made to DELETE Order Item Endpoint (Line ~1642)

**✅ Stock Restoration per Item**

- When a single OrderItem is deleted from an order, only that product's stock is restored
- The specific quantity of that item is incremented back to the product
- Order total is recalculated after item removal

## Testing Workflow

### Test 1: Successful Order with Stock Deduction

1. Check initial stock of a product

   ```
   GET /api/products/1
   Response: { stock: 100 }
   ```

2. Create order with 30 units

   ```
   POST /api/orders
   Body: {
     userId: 1,
     items: [{ productId: 1, quantity: 30, unitPrice: 50 }],
     shippingCost: 0
   }
   ```

3. Verify stock was deducted
   ```
   GET /api/products/1
   Response: { stock: 70 }  ← Should be reduced by 30
   ```

### Test 2: Reject Order with Insufficient Stock

1. Check product stock (assume it's 50)

   ```
   GET /api/products/1
   Response: { stock: 50 }
   ```

2. Try to create order with 100 units

   ```
   POST /api/orders
   Body: {
     userId: 1,
     items: [{ productId: 1, quantity: 100, unitPrice: 50 }]
   }
   ```

3. Should receive error

   ```json
   {
     "message": "Insufficient stock for Product Name. Available: 50, Requested: 100",
     "available": 50,
     "requested": 100
   }
   ```

4. Verify stock was NOT deducted (should still be 50)
   ```
   GET /api/products/1
   Response: { stock: 50 }  ← Unchanged
   ```

### Test 3: Restore Stock on Order Cancellation

1. Create order with 20 units (stock: 100 → 80)
2. Delete that order
   ```
   DELETE /api/orders/123
   ```
3. Verify stock was restored
   ```
   GET /api/products/1
   Response: { stock: 100 }  ← Back to original
   ```

### Test 4: Restore Stock on Item Removal

1. Create order with 2 items:
   - Product A: 30 units (stock: 100 → 70)
   - Product B: 50 units (stock: 200 → 150)

2. Remove Product A from order

   ```
   DELETE /api/orders/123/items/456
   ```

3. Verify only Product A stock was restored

   ```
   GET /api/products/1 (Product A)
   Response: { stock: 100 }  ← Restored

   GET /api/products/2 (Product B)
   Response: { stock: 150 }  ← Unchanged
   ```

## Key Features

### Atomicity

- All stock operations are wrapped in Prisma transactions
- Either the entire operation succeeds or fails completely
- No partial updates or inconsistent states

### Error Handling

- Detailed error messages for insufficient stock
- Graceful failure without data corruption
- Proper HTTP status codes (400 for insufficient stock, 500 for server errors)

### Logging

- Console logs for debugging:
  - "✅ Order created: ID=X, total=Y"
  - "✅ Order X deleted and stock restored"
  - "✅ Item X removed and stock restored"

## API Response Changes

### POST /api/orders - Success (201/200)

Same as before: `{ message: "Order created", order: {...} }`

### POST /api/orders - Failure (400)

New detailed error for insufficient stock:

```json
{
  "message": "Insufficient stock for Business Cards. Available: 50, Requested: 100",
  "productId": 1,
  "productName": "Business Cards",
  "available": 50,
  "requested": 100
}
```

### DELETE /api/orders/:id - Success (200)

Now includes stock restoration message: `{ message: "Order deleted and stock restored", order: {...} }`

### DELETE /api/orders/:orderId/items/:itemId - Success (200)

Now includes stock restoration message: `{ message: "Item removed from order and stock restored", order: {...} }`

## Database Notes

- Uses Prisma's atomic `{ decrement: quantity }` and `{ increment: quantity }` operators
- Works with PostgreSQL and other supported databases
- Transactions ensure consistency even with concurrent requests

## Frontend Considerations

- Frontend should handle new 400 error response with `productId` to show which item has insufficient stock
- Show warning messages to users when stock is limited or unavailable
- Consider adding stock status to product displays

---

**Status**: ✅ Implementation Complete
**Testing**: Ready for manual testing and integration tests
**Date**: May 5, 2026
