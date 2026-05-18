CREATE TABLE "CartItem" (
  "id" SERIAL NOT NULL,
  "userId" INTEGER NOT NULL,
  "productId" INTEGER,
  "title" TEXT NOT NULL,
  "price" DECIMAL(14,2) NOT NULL,
  "qty" INTEGER NOT NULL DEFAULT 1,
  "productImage" TEXT,
  "customizations" JSONB,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "CartItem_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "CartItem_userId_idx" ON "CartItem"("userId");
CREATE INDEX "CartItem_productId_idx" ON "CartItem"("productId");

ALTER TABLE "CartItem"
  ADD CONSTRAINT "CartItem_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "CartItem"
  ADD CONSTRAINT "CartItem_productId_fkey"
  FOREIGN KEY ("productId") REFERENCES "Product"("id") ON DELETE SET NULL ON UPDATE CASCADE;
