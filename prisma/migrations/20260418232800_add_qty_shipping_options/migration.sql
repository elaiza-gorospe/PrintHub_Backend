-- AlterTable
ALTER TABLE "Product" ADD COLUMN     "quantity_options" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "shipping_options" TEXT[] DEFAULT ARRAY[]::TEXT[];
