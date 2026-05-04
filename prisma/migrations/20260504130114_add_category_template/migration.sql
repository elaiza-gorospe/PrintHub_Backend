-- CreateTable
CREATE TABLE "CategoryTemplate" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "category_type" TEXT NOT NULL,
    "description" TEXT,
    "print_type" TEXT,
    "turnaround_hours" INTEGER,
    "color_options" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "size_options" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "material_options" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "side_options" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "finishing_options" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "processing_options" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "delivery_options" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "quantity_options" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "shipping_options" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "ai_prompt_rules" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CategoryTemplate_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "CategoryTemplate_name_key" ON "CategoryTemplate"("name");

-- CreateIndex
CREATE UNIQUE INDEX "CategoryTemplate_category_type_key" ON "CategoryTemplate"("category_type");
