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

  console.log("✅ Users seeded");
}

// ─── Shared option sets ─────────────────────────────────────────────────────

const COLOR_OPTIONS = [
  "Full Color (CMYK)",
  "Black & White",
  "1 Color (Spot)",
  "2 Colors (Spot)",
];

const SIDE_OPTIONS = ["Single Side", "Double Side"];

const FINISHING_OPTIONS = [
  "None",
  "Gloss Lamination",
  "Matte Lamination",
  "Spot UV",
  "Foil Stamping",
  "Embossing",
  "Die Cutting",
  "Rounded Corners",
  "Perforation",
  "Scoring & Folding",
];

const PROCESSING_OPTIONS = ["Standard", "Rush (24 hrs)", "Express (48 hrs)"];

const DELIVERY_OPTIONS = [
  "Pick Up",
  "Metro Manila Delivery",
  "Provincial Delivery",
  "Same Day (Metro Manila)",
];

// ─── Product seeds ───────────────────────────────────────────────────────────

const PRODUCT_SEEDS = [
  {
    name: "Business Cards",
    sku: "BC-STD",
    description: "Premium business cards printed on high-quality cardstock.",
    price: "350.00",
    stock: 500,
    print_type: "offset",
    turnaround_hours: 72,
    color_options: COLOR_OPTIONS,
    size_options: [
      "Standard 3.5x2 in",
      "Square 2.5x2.5 in",
      "Mini 3.5x1.5 in",
      "Folded 3.5x4 in",
    ],
    material_options: [
      "14pt Card Stock",
      "16pt Card Stock",
      "100lb Gloss Cover",
      "100lb Matte Cover",
      "Kraft Paper",
      "Linen Stock",
    ],
    side_options: SIDE_OPTIONS,
    finishing_options: FINISHING_OPTIONS,
    processing_options: PROCESSING_OPTIONS,
    delivery_options: DELIVERY_OPTIONS,
    quantity_options: [
      "100 pcs|₱350.00",
      "250 pcs|₱550.00",
      "500 pcs|₱850.00",
      "1000 pcs|₱1,200.00",
    ],
    shipping_options: ["Pick Up|Free", "Delivery|₱150.00"],
    ai_prompt_rules:
      "Generate a professional business card design. Use clean typography and ample white space. Brand colors must be used prominently. Include name, title, email, phone, and website. No clipart. No gradients unless part of approved branding. Bleed area: 0.125in on all sides. Text must be at least 7pt. Resolution: 300dpi minimum.",
  },
  {
    name: "Flyers",
    sku: "FLY-STD",
    description: "Eye-catching flyers for promotions, events, and marketing.",
    price: "15.00",
    stock: 1000,
    print_type: "digital",
    turnaround_hours: 24,
    color_options: COLOR_OPTIONS,
    size_options: [
      "A4 (8.27x11.69 in)",
      "A5 (5.83x8.27 in)",
      "Half Letter (5.5x8.5 in)",
      "DL (3.9x8.27 in)",
    ],
    material_options: [
      "80gsm Bond Paper",
      "90gsm Bond Paper",
      "100gsm Gloss Paper",
      "100gsm Matte Paper",
      "130gsm Gloss Paper",
    ],
    side_options: SIDE_OPTIONS,
    finishing_options: ["None", "Gloss Lamination", "Matte Lamination"],
    processing_options: PROCESSING_OPTIONS,
    delivery_options: DELIVERY_OPTIONS,
    quantity_options: [
      "50 pcs|₱750.00",
      "100 pcs|₱1,000.00",
      "250 pcs|₱1,800.00",
      "500 pcs|₱2,800.00",
      "1000 pcs|₱4,500.00",
    ],
    shipping_options: ["Pick Up|Free", "Delivery|₱150.00"],
    ai_prompt_rules:
      "Generate a bold, attention-grabbing flyer design. Headline must be the largest element. Use high-contrast color combinations. Include call-to-action (CTA) button or text. Contact details must be clearly visible. Safe zone: 0.25in from all edges. Text must not overlap complex backgrounds without a legible overlay. Resolution: 300dpi minimum.",
  },
  {
    name: "Brochures",
    sku: "BROC-STD",
    description:
      "Professional tri-fold or bi-fold brochures for your business.",
    price: "25.00",
    stock: 500,
    print_type: "offset",
    turnaround_hours: 48,
    color_options: COLOR_OPTIONS,
    size_options: [
      "Tri-Fold A4",
      "Bi-Fold A4",
      "Tri-Fold Letter",
      "Bi-Fold Letter",
      "Z-Fold A4",
    ],
    material_options: [
      "100gsm Gloss Paper",
      "130gsm Gloss Paper",
      "150gsm Gloss Paper",
      "100gsm Matte Paper",
      "130gsm Matte Paper",
    ],
    side_options: ["Double Side"],
    finishing_options: [
      "None",
      "Gloss Lamination",
      "Matte Lamination",
      "Spot UV",
    ],
    processing_options: PROCESSING_OPTIONS,
    delivery_options: DELIVERY_OPTIONS,
    quantity_options: [
      "100 pcs|₱2,500.00",
      "250 pcs|₱4,000.00",
      "500 pcs|₱6,500.00",
      "1000 pcs|₱10,000.00",
    ],
    shipping_options: ["Pick Up|Free", "Delivery|₱200.00"],
    ai_prompt_rules:
      "Generate a clean, structured brochure layout. Each panel must have a clear purpose: cover, inside content, back contact info. Use consistent brand colors and fonts throughout. Product/service descriptions must be concise. Include at least one image placeholder per panel. Fold lines must be accounted for in the layout. Resolution: 300dpi minimum.",
  },
  {
    name: "Stickers & Labels",
    sku: "STK-STD",
    description: "Custom stickers and labels for products and branding.",
    price: "5.00",
    stock: 2000,
    print_type: "digital",
    turnaround_hours: 24,
    color_options: COLOR_OPTIONS,
    size_options: [
      "1x1 in",
      "2x2 in",
      "3x3 in",
      "2x4 in",
      "3x5 in",
      "Custom Size",
    ],
    material_options: [
      "Glossy Vinyl",
      "Matte Vinyl",
      "Clear Vinyl",
      "White Bond",
      "Kraft Label",
      "Holographic",
    ],
    side_options: ["Single Side"],
    finishing_options: [
      "None",
      "Gloss Lamination",
      "Matte Lamination",
      "Die Cutting",
      "Kiss Cut",
      "Rounded Corners",
    ],
    processing_options: PROCESSING_OPTIONS,
    delivery_options: DELIVERY_OPTIONS,
    quantity_options: [
      "50 pcs|₱250.00",
      "100 pcs|₱400.00",
      "250 pcs|₱750.00",
      "500 pcs|₱1,200.00",
      "1000 pcs|₱2,000.00",
    ],
    shipping_options: ["Pick Up|Free", "Delivery|₱100.00"],
    ai_prompt_rules:
      "Generate a compact, visually striking sticker or label design. Design must be fully contained within the die-cut shape with 0.1in bleed. Important elements (logo, text) must be 0.125in from cut edge. Background must reach the bleed line. No thin strokes less than 0.5pt. For clear vinyl: design must work without a white background. Resolution: 300dpi minimum.",
  },
  {
    name: "Product Hang Tags",
    sku: "HT-STD",
    description: "Custom hang tags to brand your products and packaging.",
    price: "8.00",
    stock: 1000,
    print_type: "offset",
    turnaround_hours: 48,
    color_options: COLOR_OPTIONS,
    size_options: [
      "2x3.5 in",
      "2x4 in",
      "2.5x4 in",
      "3x5 in",
      "Rounded 2x3.5 in",
    ],
    material_options: [
      "300gsm Card Stock",
      "350gsm Card Stock",
      "Kraft Paper",
      "White Matte Board",
    ],
    side_options: SIDE_OPTIONS,
    finishing_options: [
      "None",
      "Gloss Lamination",
      "Matte Lamination",
      "Spot UV",
      "Foil Stamping",
      "Embossing",
      "Die Cutting",
      "Hole Punching",
    ],
    processing_options: PROCESSING_OPTIONS,
    delivery_options: DELIVERY_OPTIONS,
    quantity_options: [
      "100 pcs|₱800.00",
      "250 pcs|₱1,500.00",
      "500 pcs|₱2,500.00",
      "1000 pcs|₱4,000.00",
    ],
    shipping_options: ["Pick Up|Free", "Delivery|₱150.00"],
    ai_prompt_rules:
      "Generate an elegant, brand-consistent hang tag design. Front: logo, product name, tagline. Back: barcode placeholder, price, care instructions, or social handles. Include hole punch position at top center (0.25in from edge, 0.1875in diameter). Maintain 0.125in bleed and 0.125in safe zone. Luxury feel preferred: minimal text, strong typography. Resolution: 300dpi minimum.",
  },
  {
    name: "Posters",
    sku: "POST-STD",
    description: "Vibrant full-color posters for events and advertisements.",
    price: "80.00",
    stock: 200,
    print_type: "digital",
    turnaround_hours: 24,
    color_options: COLOR_OPTIONS,
    size_options: [
      "A3 (11.69x16.54 in)",
      "A2 (16.54x23.39 in)",
      "A1 (23.39x33.11 in)",
      "12x18 in",
      "18x24 in",
      "24x36 in",
    ],
    material_options: [
      "100gsm Gloss Paper",
      "130gsm Gloss Paper",
      "170gsm Gloss Paper",
      "100gsm Matte Paper",
      "Satin Photo Paper",
    ],
    side_options: ["Single Side"],
    finishing_options: ["None", "Gloss Lamination", "Matte Lamination"],
    processing_options: PROCESSING_OPTIONS,
    delivery_options: DELIVERY_OPTIONS,
    quantity_options: [
      "1 pc|₱80.00",
      "5 pcs|₱350.00",
      "10 pcs|₱650.00",
      "25 pcs|₱1,500.00",
      "50 pcs|₱2,500.00",
    ],
    shipping_options: ["Pick Up|Free", "Delivery|₱200.00"],
    ai_prompt_rules:
      "Generate a high-impact poster with a dominant visual element occupying at least 40% of the layout. Headline must be large and legible from a distance. Use bold, contrasting colors. Event/promo details (date, time, venue, contact) must all be present. Keep 0.25in safe zone from trim edge. Avoid cluttered layouts — use hierarchy: headline > subheadline > details. Resolution: 150dpi minimum at final print size.",
  },
  {
    name: "Tarpaulin / Banners",
    sku: "TARP-STD",
    description:
      "Large format tarpaulin and banners for outdoor and indoor use.",
    price: "350.00",
    stock: 50,
    print_type: "large-format",
    turnaround_hours: 48,
    color_options: ["Full Color (CMYK)"],
    size_options: [
      "1x2 ft",
      "2x3 ft",
      "2x4 ft",
      "3x4 ft",
      "3x6 ft",
      "4x6 ft",
      "4x8 ft",
      "Custom Size",
    ],
    material_options: [
      "13oz Vinyl",
      "16oz Vinyl (Outdoor)",
      "Mesh Vinyl (Wind-resistant)",
      "Canvas",
      "Backlit Film",
    ],
    side_options: ["Single Side"],
    finishing_options: [
      "None",
      "Eyelets / Grommets",
      "Hemming",
      "Pole Pockets",
    ],
    processing_options: PROCESSING_OPTIONS,
    delivery_options: DELIVERY_OPTIONS,
    quantity_options: [
      "1 pc|₱350.00",
      "2 pcs|₱650.00",
      "5 pcs|₱1,500.00",
      "10 pcs|₱2,800.00",
    ],
    shipping_options: ["Pick Up|Free", "Delivery|₱300.00"],
    ai_prompt_rules:
      "Generate a large format banner design viewable from a distance. Text must be large — minimum 1in tall per 10ft viewing distance. Use maximum 3 fonts. High contrast between text and background is mandatory. Include logo at top or bottom. Business name/event must be prominent. Add bleed: 0.5in on all sides. Avoid fine details — they will not be visible at distance. Resolution: 100dpi at final print size (72dpi minimum).",
  },
  {
    name: "Note Cards / Thank You Cards",
    sku: "NC-STD",
    description:
      "Personalized note cards and thank-you cards for customer appreciation.",
    price: "12.00",
    stock: 500,
    print_type: "digital",
    turnaround_hours: 48,
    color_options: COLOR_OPTIONS,
    size_options: [
      "A6 (4.13x5.83 in)",
      "A7 (5.12x7.09 in)",
      "2x3.5 in",
      "4x6 in",
    ],
    material_options: [
      "300gsm Card Stock",
      "350gsm Card Stock",
      "Linen Stock",
      "Kraft Paper",
    ],
    side_options: SIDE_OPTIONS,
    finishing_options: [
      "None",
      "Gloss Lamination",
      "Matte Lamination",
      "Spot UV",
      "Foil Stamping",
      "Rounded Corners",
    ],
    processing_options: PROCESSING_OPTIONS,
    delivery_options: DELIVERY_OPTIONS,
    quantity_options: [
      "50 pcs|₱600.00",
      "100 pcs|₱1,000.00",
      "250 pcs|₱2,000.00",
      "500 pcs|₱3,500.00",
    ],
    shipping_options: ["Pick Up|Free", "Delivery|₱150.00"],
    ai_prompt_rules:
      "Generate a warm, elegant card design. Tone must be personal and appreciative. Keep design minimal — focus on the message area. Include space for a handwritten note (blank area or lined area). Logo and brand accent should be subtle. Use soft, welcoming color palette. Bleed: 0.125in. Safe zone: 0.125in. Resolution: 300dpi minimum.",
  },
  {
    name: "Custom Notebooks",
    sku: "NB-STD",
    description: "Custom-printed notebooks for corporate giveaways and retail.",
    price: "120.00",
    stock: 100,
    print_type: "offset",
    turnaround_hours: 120,
    color_options: COLOR_OPTIONS,
    size_options: ["A4", "A5", "A6", "Pocket (3.5x5.5 in)"],
    material_options: [
      "Softcover (300gsm)",
      "Hardcover",
      "Kraft Cover",
      "Leatherette Cover",
    ],
    side_options: ["Single Side"],
    finishing_options: [
      "None",
      "Gloss Lamination",
      "Matte Lamination",
      "Spot UV",
      "Embossing",
      "Foil Stamping",
      "Spiral Binding",
      "Saddle Stitch",
    ],
    processing_options: PROCESSING_OPTIONS,
    delivery_options: DELIVERY_OPTIONS,
    quantity_options: [
      "25 pcs|₱3,000.00",
      "50 pcs|₱5,500.00",
      "100 pcs|₱10,000.00",
      "200 pcs|₱18,000.00",
    ],
    shipping_options: ["Pick Up|Free", "Delivery|₱300.00"],
    ai_prompt_rules:
      "Generate a professional notebook cover design. Cover must feature the brand logo prominently. Use clean layout with title area. Spine width must be accounted for in the layout. Back cover: include website, tagline, or barcode placeholder. Colors must be consistent with brand identity. Embossing/foil areas must be marked as separate spot layers. Bleed: 0.125in. Resolution: 300dpi minimum.",
  },
];

// ─── Category Template seeds ──────────────────────────────────────────────────

const CATEGORY_TEMPLATE_SEEDS = [
  {
    name: "T-Shirt",
    category_type: "t-shirt",
    description: "Custom-printed T-shirts with various size and color options.",
    print_type: "screen-print",
    turnaround_hours: 72,
    color_options: [
      "Full Color (CMYK) - Direct-to-Garment",
      "Full Color (Plastisol) - Screen Print",
      "Single Color - Screen Print",
      "Multi-Color - Screen Print",
    ],
    size_options: ["XS", "S", "M", "L", "XL", "2XL", "3XL", "4XL"],
    material_options: [
      "100% Cotton - 150gsm",
      "100% Cotton - 180gsm",
      "Cotton/Poly Blend - 160gsm",
      "100% Polyester - 140gsm",
      "Organic Cotton - 150gsm",
    ],
    side_options: [
      "Front Chest",
      "Back",
      "Front & Back",
      "Sleeve",
      "Full Body Wrap",
    ],
    finishing_options: [
      "None",
      "Heat Transfer",
      "Embroidery",
      "Puff Print",
      "Foil",
      "Rhinestone",
      "Glow-in-the-Dark",
      "Metallic Print",
    ],
    processing_options: [
      "Standard (5-7 days)",
      "Rush (3-4 days)",
      "Express (1-2 days)",
    ],
    delivery_options: [
      "Pick Up",
      "Metro Manila Delivery",
      "Provincial Delivery",
      "Same Day (Metro Manila)",
    ],
    quantity_options: [
      "5 pcs|₱500.00",
      "10 pcs|₱450.00",
      "25 pcs|₱420.00",
      "50 pcs|₱400.00",
      "100 pcs|₱380.00",
      "250 pcs|₱350.00",
      "500 pcs|₱320.00",
    ],
    shipping_options: [
      "Pick Up|Free",
      "Metro Delivery|₱150.00",
      "Provincial|₱300.00",
    ],
    ai_prompt_rules:
      "Generate a vibrant T-shirt design optimized for screen printing or DTG. For screen print: limit to 4-6 colors for cost efficiency. Design must work on the specified print area (chest, back, sleeve, or full). Include color specifications in CMYK or PMS if multi-color. Avoid small fine details that won't transfer well. Design should scale well across all sizes. Safe margin: 0.25in from print edges. For DTG: can use full color spectrum without limitations. Include a mockup guide indicating where the design sits on the garment. Resolution: 300dpi minimum.",
  },
];

async function seedCategoryTemplates() {
  console.log("\nSeeding category templates...");
  for (const ct of CATEGORY_TEMPLATE_SEEDS) {
    await prisma.categoryTemplate.upsert({
      where: { category_type: ct.category_type },
      update: {},
      create: {
        name: ct.name,
        category_type: ct.category_type,
        description: ct.description,
        print_type: ct.print_type || null,
        turnaround_hours: ct.turnaround_hours || null,
        ai_prompt_rules: ct.ai_prompt_rules || null,
        color_options: ct.color_options || [],
        size_options: ct.size_options || [],
        material_options: ct.material_options || [],
        side_options: ct.side_options || [],
        finishing_options: ct.finishing_options || [],
        processing_options: ct.processing_options || [],
        delivery_options: ct.delivery_options || [],
        quantity_options: ct.quantity_options || [],
        shipping_options: ct.shipping_options || [],
      },
    });
    console.log(`  ✅ ${ct.name} (${ct.category_type})`);
  }
  console.log("✅ Category templates seeded");
}

async function seedProducts() {
  console.log("\nSeeding products...");
  for (const p of PRODUCT_SEEDS) {
    await prisma.product.upsert({
      where: { sku: p.sku },
      update: {},
      create: {
        name: p.name,
        sku: p.sku,
        description: p.description,
        price: p.price,
        stock: p.stock,
        print_type: p.print_type,
        turnaround_hours: p.turnaround_hours,
        ai_prompt_rules: p.ai_prompt_rules || null,
        active: true,
        color_options: p.color_options || [],
        colorOptions: p.color_options || [],
        size_options: p.size_options || [],
        material_options: p.material_options || [],
        side_options: p.side_options || [],
        finishing_options: p.finishing_options || [],
        processing_options: p.processing_options || [],
        delivery_options: p.delivery_options || [],
        quantity_options: p.quantity_options || [],
        shipping_options: p.shipping_options || [],
        images: [],
      },
    });
    console.log(`  ✅ ${p.name} (${p.sku})`);
  }
  console.log("✅ Products seeded");
}

async function seedSampleOrder() {
  const customer = await prisma.user.findUnique({
    where: { email: "kathbuhay@gmail.com" },
  });
  const flyer = await prisma.product.findUnique({ where: { sku: "FLY-STD" } });
  const bc = await prisma.product.findUnique({ where: { sku: "BC-STD" } });

  if (customer && flyer && bc) {
    const existing = await prisma.order.findFirst({
      where: { userId: customer.id },
    });
    if (!existing) {
      const order = await prisma.order.create({
        data: {
          userId: customer.id,
          total: "1100.00",
          currency: "PHP",
          status: "pending",
          payment_status: "unpaid",
          shipping_address: "123 Sample St, Quezon City, 1100",
          items: {
            create: [
              {
                productId: flyer.id,
                quantity: 50,
                unit_price: "15.00",
                total_price: "750.00",
                customizations: {
                  size: "A4 (8.27x11.69 in)",
                  color: "Full Color (CMYK)",
                  material: "100gsm Gloss Paper",
                  side: "Double Side",
                  finishing: "None",
                  processing: "Standard",
                  delivery: "Pick Up",
                  shipping: "Pick Up|Free",
                },
              },
              {
                productId: bc.id,
                quantity: 100,
                unit_price: "3.50",
                total_price: "350.00",
                customizations: {
                  size: "Standard 3.5x2 in",
                  color: "Full Color (CMYK)",
                  material: "14pt Card Stock",
                  side: "Double Side",
                  finishing: "Gloss Lamination",
                  processing: "Standard",
                  delivery: "Pick Up",
                  shipping: "Pick Up|Free",
                },
              },
            ],
          },
        },
      });
      console.log(`\n✅ Sample order seeded (id: ${order.id})`);
    } else {
      console.log("\nℹ️  Sample order already exists, skipping");
    }
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    try {
      await seedCategoryTemplates();
      await seedProducts();
      await seedSampleOrder();
    } catch (e) {
      console.error("Seed error:", e);
    }
    await prisma.$disconnect();
  });
