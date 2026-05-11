-- AlterTable
ALTER TABLE "Product" ADD COLUMN     "print_zones" TEXT[] DEFAULT ARRAY[]::TEXT[];
