-- AlterTable
ALTER TABLE "Inquiry" ADD COLUMN     "order_id" INTEGER;

-- AlterTable
ALTER TABLE "Order" ADD COLUMN     "payment_status" TEXT NOT NULL DEFAULT 'unpaid';
