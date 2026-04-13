-- CreateTable
CREATE TABLE "Inquiry" (
    "id" SERIAL NOT NULL,
    "user_id" INTEGER,
    "product_title" TEXT,
    "subject" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "quantity" TEXT,
    "size" TEXT,
    "color" TEXT,
    "material" TEXT,
    "finishing" TEXT,
    "printing" TEXT,
    "processing" TEXT,
    "delivery" TEXT,
    "other" TEXT,
    "status" TEXT NOT NULL DEFAULT 'new',
    "quoted_price" DECIMAL(14,2),
    "admin_notes" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Inquiry_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "Inquiry" ADD CONSTRAINT "Inquiry_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
