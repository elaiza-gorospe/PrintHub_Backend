-- CreateTable
CREATE TABLE "User" (
    "id" SERIAL NOT NULL,
    "first_name" TEXT,
    "last_name" TEXT,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "phone" TEXT,
    "address" TEXT,
    "role" INTEGER NOT NULL,
    "status" TEXT,
    "last_login" TIMESTAMP(3),
    "join_date" TIMESTAMP(3),
    "gender" TEXT,
    "birthday" TIMESTAMP(3),
    "position" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ArchivedUser" (
    "id" SERIAL NOT NULL,
    "user_id" INTEGER,
    "first_name" TEXT,
    "last_name" TEXT,
    "phone" TEXT,
    "address" TEXT,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "role" INTEGER,
    "status" TEXT,
    "last_login" TIMESTAMP(3),
    "join_date" TIMESTAMP(3),
    "gender" TEXT,
    "birthday" TIMESTAMP(3),
    "position" TEXT,
    "archived_at" TIMESTAMP(3),

    CONSTRAINT "ArchivedUser_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
