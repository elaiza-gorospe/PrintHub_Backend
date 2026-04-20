-- AlterTable
ALTER TABLE "Order" ADD COLUMN     "checkout_url" TEXT,
ADD COLUMN     "payment_method" TEXT,
ADD COLUMN     "payment_reference" TEXT,
ADD COLUMN     "paymongo_session_id" TEXT;
