require("dotenv").config();
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");

const prisma = new PrismaClient();

async function main() {
  const hash = await bcrypt.hash("P@ssw0rd1", 10);

  await prisma.user.createMany({
    data: [
      {
        first_name: "Admin",
        last_name: "PrintHub",
        email: "admin@printhub.com",
        password: hash,
        role: 0,
        status: "active",
        join_date: new Date(),
      },
      {
        first_name: "Kat",
        last_name: "Bauu",
        email: "katbauu@gmail.com",
        password: hash,
        role: 0,
        status: "active",
        join_date: new Date(),
      },
      {
        first_name: "Kath",
        last_name: "Buhay",
        email: "kathbuhay@gmail.com",
        password: hash,
        role: 2,
        status: "active",
        join_date: new Date(),
      },
    ],
    skipDuplicates: true,
  });

  console.log("Seed complete");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
