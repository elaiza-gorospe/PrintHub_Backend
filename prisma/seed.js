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

async function seedProductsAndOrder() {
  // create sample products
  const flyer = await prisma.product.create({
    data: {
      name: "A4 Full Color Flyer",
      sku: "FLY-A4",
      description: "Full color double-sided A4 flyer",
      price: "20.00",
      stock: 100,
      print_type: "digital",
      turnaround_hours: 24,
    },
  });

  const banner = await prisma.product.create({
    data: {
      name: "Roll-up Banner 800x2000mm",
      sku: "BANNER-800x2000",
      description: "Large roll-up banner for events",
      price: "1500.00",
      stock: 20,
      print_type: "large-format",
      turnaround_hours: 72,
    },
  });

  const tshirt = await prisma.product.create({
    data: {
      name: "Custom Printed T-Shirt",
      sku: "TSHIRT-STD",
      description: "Cotton T-shirt with custom print",
      price: "300.00",
      stock: 50,
      material: "cotton",
      print_type: "dtg",
      turnaround_hours: 48,
    },
  });

  // create a sample order for the seeded customer if exists
  const customer = await prisma.user.findUnique({
    where: { email: "kathbuhay@gmail.com" },
  });
  if (customer) {
    const order = await prisma.order.create({
      data: {
        userId: customer.id,
        total: "500.00",
        currency: "PHP",
        status: "pending",
        shipping_address: "Sample Address",
        items: {
          create: [
            {
              productId: flyer.id,
              quantity: 5,
              unit_price: "20.00",
              total_price: "100.00",
              customizations: { finish: "gloss" },
            },
            {
              productId: tshirt.id,
              quantity: 1,
              unit_price: "300.00",
              total_price: "300.00",
              customizations: { size: "L", color: "black" },
            },
          ],
        },
      },
    });

    console.log("Seeded sample order id:", order.id);
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    // also insert products and an order
    try {
      await seedProductsAndOrder();
    } catch (e) {
      console.error("Seed products error", e);
    }
    await prisma.$disconnect();
  });
