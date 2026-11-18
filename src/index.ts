type Product = {
  id: string;
  name: string;
  category: "medicine" | "clothing" | "food";
  description: string;
  price: number;
  currency: "GHS";
  image?: string;
  inStock: boolean;
};

const demoProducts: Product[] = [
  { id: "food-001", name: "Jollof Rice with Chicken", category: "food", description: "A freshly prepared serving. Select your preferred portion at checkout.", price: 65, currency: "GHS", inStock: true },
  { id: "clothes-001", name: "Classic Cotton T-Shirt", category: "clothing", description: "Everyday cotton T-shirt. Available in multiple sizes and colours.", price: 90, currency: "GHS", inStock: true },
  { id: "medicine-001", name: "First Aid Essentials Kit", category: "medicine", description: "A general first-aid kit. Ask a pharmacist about medicines and treatment choices.", price: 120, currency: "GHS", inStock: true }
];

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      return json({ ok: true, app: "conversational-store", stage: "prototype" });
    }

    if (url.pathname === "/api/products" && request.method === "GET") {
      const term = (url.searchParams.get("q") || "").trim().toLowerCase();
      const category = url.searchParams.get("category");
      const products = demoProducts.filter((product) => {
        const matchesTerm = !term || [product.name, product.description, product.category].some((value) => value.toLowerCase().includes(term));
        const matchesCategory = !category || product.category === category;
        return matchesTerm && matchesCategory;
      });
      return json({ products, demo: true });
    }

    if (url.pathname === "/api/chat" && request.method === "POST") {
      let body: { message?: string };
      try {
        body = await request.json() as { message?: string };
      } catch {
        return json({ error: "Please send a valid message." }, 400);
      }

      const message = (body.message || "").trim();
      if (!message) return json({ error: "Type a message to get started." }, 400);

      const matches = demoProducts.filter((product) =>
        [product.name, product.description, product.category].some((value) => value.toLowerCase().includes(message.toLowerCase()))
      );

      return json({
        reply: matches.length
          ? "I found a few items that may match. These are sample products while the store catalogue is being connected."
          : "Welcome! Tell me what you need, or mention food, clothing, or medicine and I’ll help you find it. The AI shopping assistant will be connected in the next build stage.",
        products: matches.length ? matches : demoProducts,
        demo: true
      });
    }

    return new Response("Not found", { status: 404 });
  }
};
