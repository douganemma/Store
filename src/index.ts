type StoreEnv = {
  DB: D1Database;
  IMAGES: R2Bucket;
  ASSETS: Fetcher;
  AI: Ai;
  ADMIN_SETUP_TOKEN?: string;
  WHATSAPP_VERIFY_TOKEN?: string;
  WHATSAPP_APP_SECRET?: string;
};

type AdminRow = { id: string; email: string; password_hash: string };
type ProductRow = {
  id: string; sku: string; name: string; category_slug: string; description: string;
  price_pesewas: number; stock_quantity: number; is_active: number; image_key: string | null;
  attributes_json: string; requires_prescription: number; batch_number: string | null;
  expiry_date: string | null; created_at: number; updated_at: number;
};

const SESSION_SECONDS = 60 * 60 * 24 * 7;
// Cloudflare Workers WebCrypto currently caps PBKDF2 iterations at 100,000.
const PASSWORD_ITERATIONS = 100000;
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const ALLOWED_IMAGES: Record<string, string> = {
  "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/avif": "avif"
};

const json = (data: unknown, status = 200, headers: HeadersInit = {}) => {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("content-type", "application/json; charset=utf-8");
  responseHeaders.set("cache-control", "no-store");
  return new Response(JSON.stringify(data), { status, headers: responseHeaders });
};

const nowSeconds = () => Math.floor(Date.now() / 1000);
const encoder = new TextEncoder();

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
}

async function passwordHash(password: string): Promise<string> {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = new ArrayBuffer(16);
  new Uint8Array(salt).set(saltBytes);
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PASSWORD_ITERATIONS }, key, 256);
  return "pbkdf2$" + PASSWORD_ITERATIONS + "$" + bytesToBase64Url(saltBytes) + "$" + bytesToBase64Url(new Uint8Array(bits));
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000) return false;
  const saltBytes = base64UrlToBytes(parts[2]);
  const salt = new ArrayBuffer(saltBytes.length);
  new Uint8Array(salt).set(saltBytes);
  const expected = base64UrlToBytes(parts[3]);
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, expected.length * 8));
  if (bits.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < bits.length; i++) diff |= bits[i] ^ expected[i];
  return diff === 0;
}

function cookieValue(request: Request, name: string): string | null {
  const cookie = request.headers.get("cookie") || "";
  for (const part of cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=") || null;
  }
  return null;
}

function sessionCookie(token: string, request: Request): string {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return "mm_admin=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" + SESSION_SECONDS + secure;
}

async function currentAdmin(request: Request, env: StoreEnv): Promise<AdminRow | null> {
  const token = cookieValue(request, "mm_admin");
  if (!token || token.length < 32 || token.length > 128) return null;
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    "SELECT a.id, a.email, a.password_hash FROM admin_sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash = ? AND s.expires_at > ?"
  ).bind(tokenHash, nowSeconds()).first<AdminRow>();
  return row || null;
}

function safeAdmin(admin: AdminRow) {
  return { id: admin.id, email: admin.email };
}

function originAllowed(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}

async function requireAdmin(request: Request, env: StoreEnv): Promise<AdminRow | Response> {
  if (request.method !== "GET" && request.method !== "HEAD" && !originAllowed(request)) {
    return json({ error: "Cross-origin request blocked." }, 403);
  }
  const admin = await currentAdmin(request, env);
  return admin || json({ error: "Admin sign-in required." }, 401);
}

function isResponse(value: AdminRow | Response): value is Response {
  return value instanceof Response;
}

function slugify(value: string): string {
  return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);
}

function productOutput(row: ProductRow) {
  return {
    id: row.id, sku: row.sku, name: row.name, category: row.category_slug,
    description: row.description, price: row.price_pesewas / 100,
    pricePesewas: row.price_pesewas, currency: "GHS",
    stockQuantity: row.stock_quantity, inStock: row.stock_quantity > 0,
    isActive: Boolean(row.is_active), imageKey: row.image_key,
    imageUrl: row.image_key ? "/api/media/" + encodeURIComponent(row.image_key) : null,
    attributes: JSON.parse(row.attributes_json || "{}"),
    requiresPrescription: Boolean(row.requires_prescription),
    batchNumber: row.batch_number, expiryDate: row.expiry_date
  };
}

async function listProducts(env: StoreEnv, options: { admin?: boolean; q?: string; category?: string } = {}) {
  const where: string[] = [];
  const values: (string | number)[] = [];
  if (!options.admin) where.push("p.is_active = 1");
  if (options.category) { where.push("p.category_slug = ?"); values.push(options.category); }
  if (options.q) {
    where.push("(lower(p.name) LIKE ? OR lower(p.description) LIKE ? OR lower(p.sku) LIKE ?)");
    const term = "%" + options.q.toLowerCase().slice(0, 80) + "%";
    values.push(term, term, term);
  }
  const sql = "SELECT p.* FROM products p" + (where.length ? " WHERE " + where.join(" AND ") : "") + " ORDER BY p.created_at DESC LIMIT 100";
  const result = await env.DB.prepare(sql).bind(...values).all<ProductRow>();
  return (result.results || []).map(productOutput);
}

async function createSession(admin: AdminRow, request: Request, env: StoreEnv): Promise<Response> {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = bytesToBase64Url(tokenBytes);
  const expiresAt = nowSeconds() + SESSION_SECONDS;
  await env.DB.prepare("INSERT INTO admin_sessions (token_hash, admin_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
    .bind(await sha256(token), admin.id, expiresAt, nowSeconds()).run();
  return json({ admin: safeAdmin(admin) }, 200, { "set-cookie": sessionCookie(token, request) });
}

async function handleAuth(request: Request, env: StoreEnv, path: string): Promise<Response | null> {
  if (request.method === "POST" && path.startsWith("/api/admin/") && !originAllowed(request)) {
    return json({ error: "Cross-origin request blocked." }, 403);
  }
  if (path === "/api/admin/status" && request.method === "GET") {
    const row = await env.DB.prepare("SELECT COUNT(*) AS count FROM admins").first<{ count: number }>();
    return json({ needsSetup: Number(row?.count || 0) === 0 });
  }

  if (path === "/api/admin/me" && request.method === "GET") {
    const admin = await currentAdmin(request, env);
    return admin ? json({ admin: safeAdmin(admin) }) : json({ error: "Not signed in." }, 401);
  }

  if (path === "/api/admin/setup" && request.method === "POST") {
    if (!env.ADMIN_SETUP_TOKEN || env.ADMIN_SETUP_TOKEN.length < 32) return json({ error: "Admin setup requires an ADMIN_SETUP_TOKEN secret with at least 32 characters." }, 503);
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM admins").first<{ count: number }>();
    if (Number(count?.count || 0) > 0) return json({ error: "Admin setup has already been completed." }, 409);
    let body: { setupToken?: string; email?: string; password?: string };
    try { body = await request.json() as typeof body; } catch { return json({ error: "Invalid JSON body." }, 400); }
    const supplied = String(body.setupToken || "");
    if (!supplied || !(await constantTimeTextEqual(supplied, env.ADMIN_SETUP_TOKEN))) return json({ error: "Invalid setup token." }, 403);
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Enter a valid email address." }, 400);
    if (password.length < 12 || password.length > 128) return json({ error: "Use a password with at least 12 characters." }, 400);
    const admin: AdminRow = { id: crypto.randomUUID(), email, password_hash: await passwordHash(password) };
    try {
      const inserted = await env.DB.prepare("INSERT INTO admins (id, email, password_hash, created_at) SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM admins)")
        .bind(admin.id, email, admin.password_hash, nowSeconds()).run();
      if (Number(inserted.meta.changes || 0) !== 1) return json({ error: "Admin setup has already been completed." }, 409);
    } catch {
      return json({ error: "An admin account already exists or the email is already registered." }, 409);
    }
    return createSession(admin, request, env);
  }

  if (path === "/api/admin/login" && request.method === "POST") {
    let body: { email?: string; password?: string };
    try { body = await request.json() as typeof body; } catch { return json({ error: "Invalid JSON body." }, 400); }
    const password = String(body.password || "");
    if (password.length > 128) return json({ error: "Password is too long." }, 400);
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const ipHash = await sha256(ip);
    await env.DB.prepare("DELETE FROM login_attempts WHERE attempted_at < ?").bind(nowSeconds() - 86400).run();
    const recent = await env.DB.prepare("SELECT COUNT(*) AS count FROM login_attempts WHERE ip_hash = ? AND attempted_at > ?")
      .bind(ipHash, nowSeconds() - 900).first<{ count: number }>();
    if (Number(recent?.count || 0) >= 8) return json({ error: "Too many sign-in attempts. Try again in 15 minutes." }, 429);
    await env.DB.prepare("INSERT INTO login_attempts (id, ip_hash, attempted_at) VALUES (?, ?, ?)")
      .bind(crypto.randomUUID(), ipHash, nowSeconds()).run();
    const email = String(body.email || "").trim().toLowerCase();
    const admin = await env.DB.prepare("SELECT id, email, password_hash FROM admins WHERE email = ? COLLATE NOCASE")
      .bind(email).first<AdminRow>();
    const valid = admin ? await verifyPassword(password, admin.password_hash) : false;
    if (!admin || !valid) return json({ error: "Email or password is incorrect." }, 401);
    await env.DB.prepare("UPDATE admins SET last_login_at = ? WHERE id = ?").bind(nowSeconds(), admin.id).run();
    return createSession(admin, request, env);
  }

  if (path === "/api/admin/logout" && request.method === "POST") {
    const token = cookieValue(request, "mm_admin");
    if (token) await env.DB.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").bind(await sha256(token)).run();
    const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
    return json({ ok: true }, 200, { "set-cookie": "mm_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" + secure });
  }
  return null;
}

async function constantTimeTextEqual(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([sha256(a), sha256(b)]);
  let diff = ha.length ^ hb.length;
  for (let i = 0; i < Math.min(ha.length, hb.length); i++) diff |= ha.charCodeAt(i) ^ hb.charCodeAt(i);
  return diff === 0;
}

async function handleProducts(request: Request, env: StoreEnv, path: string): Promise<Response | null> {
  if (path === "/api/products" && request.method === "GET") {
    const url = new URL(request.url);
    return json({ products: await listProducts(env, { q: url.searchParams.get("q") || "", category: url.searchParams.get("category") || "" }) });
  }
  if (path === "/api/categories" && request.method === "GET") {
    const rows = await env.DB.prepare("SELECT slug, name, description FROM categories WHERE is_active = 1 ORDER BY name").all();
    return json({ categories: rows.results || [] });
  }
  if (path === "/api/admin/products" && request.method === "GET") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    return json({ products: await listProducts(env, { admin: true }) });
  }
  if (path === "/api/admin/products" && request.method === "POST") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    let body: Record<string, unknown>;
    try { body = await request.json() as Record<string, unknown>; } catch { return json({ error: "Invalid JSON body." }, 400); }
    const values = validateProduct(body); if (values instanceof Response) return values;
    const category = await env.DB.prepare("SELECT slug FROM categories WHERE slug = ? AND is_active = 1").bind(values.category).first();
    if (!category) return json({ error: "Choose an active category." }, 400);
    const id = crypto.randomUUID(); const now = nowSeconds();
    try {
      await env.DB.prepare("INSERT INTO products (id, sku, name, category_slug, description, price_pesewas, stock_quantity, is_active, image_key, attributes_json, requires_prescription, batch_number, expiry_date, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(id, values.sku, values.name, values.category, values.description, values.pricePesewas, values.stockQuantity, values.isActive ? 1 : 0, values.imageKey, JSON.stringify(values.attributes), values.requiresPrescription ? 1 : 0, values.batchNumber, values.expiryDate, now, now).run();
    } catch { return json({ error: "Could not save product. Check that its SKU is unique." }, 409); }
    const row = await env.DB.prepare("SELECT * FROM products WHERE id = ?").bind(id).first<ProductRow>();
    return json({ product: row ? productOutput(row) : null }, 201);
  }
  const productMatch = path.match(/^\/api\/admin\/products\/([a-zA-Z0-9-]+)$/);
  if (productMatch && (request.method === "PUT" || request.method === "DELETE")) {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    const id = productMatch[1];
    const existing = await env.DB.prepare("SELECT * FROM products WHERE id = ?").bind(id).first<ProductRow>();
    if (!existing) return json({ error: "Product not found." }, 404);
    if (request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM products WHERE id = ?").bind(id).run();
      if (existing.image_key) await env.IMAGES.delete(existing.image_key);
      return json({ ok: true });
    }
    let body: Record<string, unknown>;
    try { body = await request.json() as Record<string, unknown>; } catch { return json({ error: "Invalid JSON body." }, 400); }
    const values = validateProduct(body); if (values instanceof Response) return values;
    const category = await env.DB.prepare("SELECT slug FROM categories WHERE slug = ? AND is_active = 1").bind(values.category).first();
    if (!category) return json({ error: "Choose an active category." }, 400);
    try {
      await env.DB.prepare("UPDATE products SET sku=?, name=?, category_slug=?, description=?, price_pesewas=?, stock_quantity=?, is_active=?, image_key=?, attributes_json=?, requires_prescription=?, batch_number=?, expiry_date=?, updated_at=? WHERE id=?")
        .bind(values.sku, values.name, values.category, values.description, values.pricePesewas, values.stockQuantity, values.isActive ? 1 : 0, values.imageKey, JSON.stringify(values.attributes), values.requiresPrescription ? 1 : 0, values.batchNumber, values.expiryDate, nowSeconds(), id).run();
    } catch { return json({ error: "Could not update product. Check that its SKU is unique." }, 409); }
    if (existing.image_key && existing.image_key !== values.imageKey) await env.IMAGES.delete(existing.image_key);
    const row = await env.DB.prepare("SELECT * FROM products WHERE id = ?").bind(id).first<ProductRow>();
    return json({ product: row ? productOutput(row) : null });
  }
  return null;
}

function validateProduct(body: Record<string, unknown>) {
  const sku = String(body.sku || "").trim().toUpperCase();
  const name = String(body.name || "").trim();
  const category = String(body.category || "").trim();
  const description = String(body.description || "").trim();
  const price = Number(body.price);
  const stock = Number(body.stockQuantity);
  const pricePesewas = Math.round(price * 100);
  const stockQuantity = Math.floor(stock);
  const imageKey = body.imageKey ? String(body.imageKey) : null;
  const attributes = body.attributes && typeof body.attributes === "object" && !Array.isArray(body.attributes) ? body.attributes : {};
  const requiresPrescription = body.requiresPrescription === true;
  const batchNumber = body.batchNumber ? String(body.batchNumber).trim().slice(0, 80) : null;
  const expiryDate = body.expiryDate ? String(body.expiryDate).trim() : null;
  const isActive = body.isActive !== false;
  if (!/^[A-Z0-9_-]{2,40}$/.test(sku)) return json({ error: "SKU must be 2–40 letters, numbers, dashes or underscores." }, 400);
  if (name.length < 2 || name.length > 120) return json({ error: "Product name must be 2–120 characters." }, 400);
  if (!["food", "clothing", "medicine"].includes(category)) return json({ error: "Choose a valid category." }, 400);
  if (!Number.isFinite(price) || price < 0 || price > 10000000) return json({ error: "Enter a valid price in Ghana cedis." }, 400);
  if (!Number.isFinite(stock) || stockQuantity < 0 || stockQuantity > 10000000) return json({ error: "Enter a valid stock quantity." }, 400);
  if (description.length > 2000) return json({ error: "Description is too long." }, 400);
  if (imageKey && !/^products\/[0-9a-f-]+\.(jpg|png|webp|avif)$/.test(imageKey)) return json({ error: "Invalid product image." }, 400);
  if (category === "medicine" && requiresPrescription && !batchNumber) return json({ error: "Prescription products must include a batch number before being listed." }, 400);
  if (expiryDate && !/^\d{4}-\d{2}-\d{2}$/.test(expiryDate)) return json({ error: "Use YYYY-MM-DD for expiry date." }, 400);
  return { sku, name, category, description, pricePesewas, stockQuantity, imageKey, attributes, requiresPrescription, batchNumber, expiryDate, isActive };
}

async function handleCategories(request: Request, env: StoreEnv, path: string): Promise<Response | null> {
  if (path === "/api/admin/categories" && request.method === "GET") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    const rows = await env.DB.prepare("SELECT slug, name, description, is_active AS isActive FROM categories ORDER BY name").all();
    return json({ categories: rows.results || [] });
  }
  if (path === "/api/admin/categories" && request.method === "POST") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    let body: { name?: string; description?: string };
    try { body = await request.json() as typeof body; } catch { return json({ error: "Invalid JSON body." }, 400); }
    const name = String(body.name || "").trim().slice(0, 80);
    const slug = slugify(name);
    if (name.length < 2 || !slug) return json({ error: "Enter a category name." }, 400);
    try {
      await env.DB.prepare("INSERT INTO categories (id, slug, name, description, is_active, created_at) VALUES (?, ?, ?, ?, 1, ?)")
        .bind(crypto.randomUUID(), slug, name, String(body.description || "").slice(0, 500), nowSeconds()).run();
    } catch { return json({ error: "That category already exists." }, 409); }
    return json({ category: { slug, name } }, 201);
  }
  const match = path.match(/^\/api\/admin\/categories\/([a-z0-9-]+)$/);
  if (match && (request.method === "PUT" || request.method === "DELETE")) {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    const slug = match[1];
    if (request.method === "DELETE") {
      const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM products WHERE category_slug = ?").bind(slug).first<{ count: number }>();
      if (Number(count?.count || 0) > 0) return json({ error: "Move or remove products in this category before deleting it." }, 409);
      await env.DB.prepare("DELETE FROM categories WHERE slug = ?").bind(slug).run();
      return json({ ok: true });
    }
    let body: { name?: string; description?: string; isActive?: boolean };
    try { body = await request.json() as typeof body; } catch { return json({ error: "Invalid JSON body." }, 400); }
    const name = String(body.name || "").trim().slice(0, 80);
    if (name.length < 2) return json({ error: "Enter a category name." }, 400);
    await env.DB.prepare("UPDATE categories SET name = ?, description = ?, is_active = ? WHERE slug = ?")
      .bind(name, String(body.description || "").slice(0, 500), body.isActive === false ? 0 : 1, slug).run();
    return json({ ok: true });
  }
  return null;
}

async function handleUploads(request: Request, env: StoreEnv): Promise<Response> {
  const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_IMAGE_BYTES + 64 * 1024) return json({ error: "Images must be smaller than 5 MB." }, 413);
  const form = await request.formData();
  const file = form.get("file");
  if (!(file instanceof File)) return json({ error: "Choose an image file." }, 400);
  if (file.size < 1 || file.size > MAX_IMAGE_BYTES) return json({ error: "Images must be smaller than 5 MB." }, 413);
  const extension = ALLOWED_IMAGES[file.type];
  if (!extension) return json({ error: "Use a JPG, PNG, WebP or AVIF image." }, 415);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const validSignature =
    (file.type === "image/jpeg" && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) ||
    (file.type === "image/png" && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) ||
    (file.type === "image/webp" && String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" && String.fromCharCode(...bytes.slice(8, 12)) === "WEBP") ||
    (file.type === "image/avif" && String.fromCharCode(...bytes.slice(4, 8)) === "ftyp" && ["avif", "avis"].includes(String.fromCharCode(...bytes.slice(8, 12))));
  if (!validSignature) return json({ error: "The image file contents do not match its image type." }, 415);
  const key = "products/" + crypto.randomUUID() + "." + extension;
  await env.IMAGES.put(key, bytes, {
    httpMetadata: { contentType: file.type, cacheControl: "public, max-age=31536000, immutable" },
    customMetadata: { uploadedBy: admin.id }
  });
  return json({ imageKey: key, imageUrl: "/api/media/" + encodeURIComponent(key) }, 201);
}

async function handleMedia(request: Request, env: StoreEnv, path: string): Promise<Response | null> {
  if (request.method !== "GET" || !path.startsWith("/api/media/")) return null;
  const key = decodeURIComponent(path.slice("/api/media/".length));
  if (!/^products\/[0-9a-f-]+\.(jpg|png|webp|avif)$/.test(key)) return new Response("Not found", { status: 404 });
  const object = await env.IMAGES.get(key);
  if (!object) return new Response("Not found", { status: 404 });
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("cache-control", "public, max-age=31536000, immutable");
  headers.set("x-content-type-options", "nosniff");
  return new Response(object.body, { headers });
}


const CART_SECONDS = 60 * 60 * 24 * 30;
function cartCookie(token: string, request: Request): string {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return "mm_cart=" + token + "; HttpOnly; SameSite=Lax; Path=/; Max-Age=" + CART_SECONDS + secure;
}
async function cartIdentity(request: Request, env: StoreEnv) {
  let token = cookieValue(request, "mm_cart");
  let setCookie: string | null = null;
  if (!token || token.length < 32 || token.length > 128) {
    token = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    setCookie = cartCookie(token, request);
  }
  const id = await sha256(token);
  await env.DB.prepare("INSERT INTO carts (id, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at, expires_at=excluded.expires_at")
    .bind(id, nowSeconds(), nowSeconds(), nowSeconds() + CART_SECONDS).run();
  return { id, setCookie };
}
async function readCart(env: StoreEnv, cartId: string) {
  const rows = await env.DB.prepare("SELECT p.*, ci.quantity FROM cart_items ci JOIN products p ON p.id=ci.product_id WHERE ci.cart_id=? AND p.is_active=1 ORDER BY p.name")
    .bind(cartId).all<ProductRow & { quantity: number }>();
  const items = (rows.results || []).map(row => ({ product: productOutput(row), quantity: row.quantity, lineTotalPesewas: row.price_pesewas * row.quantity }));
  return { items, subtotalPesewas: items.reduce((sum, item) => sum + item.lineTotalPesewas, 0), itemCount: items.reduce((sum, item) => sum + item.quantity, 0) };
}
async function handleCart(request: Request, env: StoreEnv, path: string): Promise<Response | null> {
  if (path === "/api/cart" && request.method === "GET") {
    const identity = await cartIdentity(request, env);
    return json(await readCart(env, identity.id), 200, identity.setCookie ? { "set-cookie": identity.setCookie } : {});
  }
  if (path === "/api/cart/items" && request.method === "POST") {
    if (!originAllowed(request)) return json({ error: "Cross-origin request blocked." }, 403);
    let body: { productId?: string; quantity?: number };
    try { body = await request.json() as typeof body; } catch { return json({ error: "Invalid request." }, 400); }
    const productId = String(body.productId || "");
    const quantity = Number(body.quantity ?? 1);
    if (!/^[a-zA-Z0-9-]{1,80}$/.test(productId) || !Number.isInteger(quantity) || quantity < 1 || quantity > 99) return json({ error: "Choose a valid product and quantity." }, 400);
    const product = await env.DB.prepare("SELECT id, stock_quantity, is_active, requires_prescription FROM products WHERE id=?").bind(productId).first<{id:string;stock_quantity:number;is_active:number;requires_prescription:number}>();
    if (!product || !product.is_active) return json({ error: "This product is no longer available." }, 404);
    if (product.requires_prescription) return json({ error: "This product requires prescription verification and cannot be ordered online yet. Please contact the store." }, 400);
    const identity = await cartIdentity(request, env);
    const existing = await env.DB.prepare("SELECT quantity FROM cart_items WHERE cart_id=? AND product_id=?").bind(identity.id, productId).first<{quantity:number}>();
    const next = Math.min(99, (existing?.quantity || 0) + quantity);
    if (next > product.stock_quantity) return json({ error: "Only " + product.stock_quantity + " item(s) are currently in stock." }, 409);
    await env.DB.prepare("INSERT INTO cart_items (cart_id, product_id, quantity, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(cart_id, product_id) DO UPDATE SET quantity=excluded.quantity, updated_at=excluded.updated_at")
      .bind(identity.id, productId, next, nowSeconds()).run();
    return json(await readCart(env, identity.id), 200, identity.setCookie ? { "set-cookie": identity.setCookie } : {});
  }
  const remove = path.match(/^\/api\/cart\/items\/([a-zA-Z0-9-]+)$/);
  if (remove && request.method === "DELETE") {
    if (!originAllowed(request)) return json({ error: "Cross-origin request blocked." }, 403);
    const identity = await cartIdentity(request, env);
    await env.DB.prepare("DELETE FROM cart_items WHERE cart_id=? AND product_id=?").bind(identity.id, remove[1]).run();
    return json(await readCart(env, identity.id), 200, identity.setCookie ? { "set-cookie": identity.setCookie } : {});
  }
  return null;
}
async function handleCheckout(request: Request, env: StoreEnv): Promise<Response | null> {
  if (request.method !== "POST" || new URL(request.url).pathname !== "/api/checkout") return null;
  if (!originAllowed(request)) return json({ error: "Cross-origin request blocked." }, 403);
  let body: { name?: string; phone?: string; email?: string; address?: string; notes?: string };
  try { body = await request.json() as typeof body; } catch { return json({ error: "Please complete the checkout form." }, 400); }
  const name = String(body.name || "").trim().slice(0, 100);
  const phone = String(body.phone || "").trim().replace(/[\s()-]/g, "");
  const email = String(body.email || "").trim().slice(0, 160);
  const address = String(body.address || "").trim().slice(0, 500);
  const notes = String(body.notes || "").trim().slice(0, 500);
  if (name.length < 2) return json({ error: "Enter your full name." }, 400);
  if (!/^(?:\+233|0)\d{9}$/.test(phone)) return json({ error: "Enter a valid Ghana phone number, e.g. 0241234567 or +233241234567." }, 400);
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Enter a valid email address." }, 400);
  if (address.length < 8) return json({ error: "Enter your complete delivery address." }, 400);
  const identity = await cartIdentity(request, env);
  const cart = await readCart(env, identity.id);
  if (!cart.items.length) return json({ error: "Your cart is empty." }, 400);
  if (cart.items.some(item => item.product.requiresPrescription)) return json({ error: "Your cart contains an item that requires prescription verification. Remove it or contact the store." }, 400);
  const orderId = crypto.randomUUID();
  const orderNumber = "MM-" + Date.now().toString(36).toUpperCase() + "-" + bytesToBase64Url(crypto.getRandomValues(new Uint8Array(3))).toUpperCase();
  const now = nowSeconds();
  // Conditional stock deductions prevent checkout from selling more than the available quantity.
  const deductions = cart.items.map(item => env.DB.prepare("UPDATE products SET stock_quantity=stock_quantity-?, updated_at=? WHERE id=? AND is_active=1 AND stock_quantity>=?")
    .bind(item.quantity, now, item.product.id, item.quantity));
  const results = await env.DB.batch(deductions);
  const failed = results.some(result => Number(result.meta.changes || 0) !== 1);
  if (failed) {
    await env.DB.batch(cart.items.filter((_, index) => Number(results[index]?.meta.changes || 0) === 1)
      .map(item => env.DB.prepare("UPDATE products SET stock_quantity=stock_quantity+?, updated_at=? WHERE id=?").bind(item.quantity, now, item.product.id)));
    return json({ error: "One or more items just went out of stock. Please review your cart." }, 409);
  }
  const total = cart.subtotalPesewas;
  const orderStatements = [
    env.DB.prepare("INSERT INTO orders (id, order_number, customer_name, phone, email, delivery_address, delivery_notes, subtotal_pesewas, delivery_fee_pesewas, total_pesewas, currency, payment_method, payment_status, order_status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 'GHS', 'cash_on_delivery', 'pay_on_delivery', 'pending_confirmation', ?, ?)")
      .bind(orderId, orderNumber, name, phone, email, address, notes, total, total, now, now),
    ...cart.items.map(item => env.DB.prepare("INSERT INTO order_items (id, order_id, product_id, product_name, sku, unit_price_pesewas, quantity, line_total_pesewas) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(crypto.randomUUID(), orderId, item.product.id, item.product.name, item.product.sku, item.product.pricePesewas, item.quantity, item.lineTotalPesewas)),
    env.DB.prepare("DELETE FROM cart_items WHERE cart_id=?").bind(identity.id)
  ];
  try { await env.DB.batch(orderStatements); }
  catch (error) {
    await env.DB.batch(cart.items.map(item => env.DB.prepare("UPDATE products SET stock_quantity=stock_quantity+?, updated_at=? WHERE id=?").bind(item.quantity, now, item.product.id)));
    throw error;
  }
  return json({ ok: true, orderNumber, total: total / 100, currency: "GHS", paymentMethod: "Cash on delivery", message: "Order received. Pay the delivery agent when your order arrives." }, 201);
}
async function handleAdminOrders(request: Request, env: StoreEnv, path: string): Promise<Response | null> {
  if (path === "/api/admin/orders" && request.method === "GET") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    const rows = await env.DB.prepare("SELECT * FROM orders ORDER BY created_at DESC LIMIT 200").all<Record<string, unknown>>();
    const orders = await Promise.all((rows.results || []).map(async order => {
      const items = await env.DB.prepare("SELECT product_name AS name, sku, unit_price_pesewas AS unitPricePesewas, quantity, line_total_pesewas AS lineTotalPesewas FROM order_items WHERE order_id=?").bind(order.id).all();
      return { ...order, items: items.results || [] };
    }));
    return json({ orders });
  }
  const match = path.match(/^\/api\/admin\/orders\/([a-f0-9-]+)$/);
  if (match && request.method === "PATCH") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    let body: { status?: string }; try { body = await request.json() as typeof body; } catch { return json({ error: "Invalid request." }, 400); }
    const allowed = ["pending_confirmation", "confirmed", "processing", "dispatched", "delivered", "cancelled"];
    if (!allowed.includes(String(body.status))) return json({ error: "Choose a valid order status." }, 400);
    const order = await env.DB.prepare("SELECT id, order_status FROM orders WHERE id=?").bind(match[1]).first<{id:string;order_status:string}>();
    if (!order) return json({ error: "Order not found." }, 404);
    if (order.order_status === "cancelled" && body.status !== "cancelled") return json({ error: "Cancelled orders cannot be reopened. Create a new order instead." }, 409);
    if (body.status === "cancelled" && order.order_status !== "cancelled") {
      const items = await env.DB.prepare("SELECT product_id, quantity FROM order_items WHERE order_id=? AND product_id IS NOT NULL").bind(order.id).all<{product_id:string;quantity:number}>();
      await env.DB.batch((items.results || []).map(item => env.DB.prepare("UPDATE products SET stock_quantity=stock_quantity+?, updated_at=? WHERE id=?").bind(item.quantity, nowSeconds(), item.product_id)));
    }
    await env.DB.prepare("UPDATE orders SET order_status=?, updated_at=? WHERE id=?").bind(body.status, nowSeconds(), match[1]).run();
    return json({ ok: true });
  }
  return null;
}


type StoreSettingsRow = {
  id: number; business_name: string; tagline: string; description: string; phone: string; email: string;
  address: string; opening_hours: string; greeting_message: string; away_message: string;
  away_enabled: number; updated_at: number;
};

async function handleBusinessTools(request: Request, env: StoreEnv, path: string): Promise<Response | null> {
  if (path === "/api/storefront" && request.method === "GET") {
    const settings = await env.DB.prepare("SELECT * FROM store_settings WHERE id=1").first<StoreSettingsRow>();
    return json({ settings: settings ? {
      businessName: settings.business_name, tagline: settings.tagline, description: settings.description,
      phone: settings.phone, email: settings.email, address: settings.address, openingHours: settings.opening_hours,
      greetingMessage: settings.greeting_message, awayMessage: settings.away_message, awayEnabled: Boolean(settings.away_enabled)
    } : null });
  }
  if (path === "/api/collections" && request.method === "GET") {
    const rows = await env.DB.prepare("SELECT id, slug, name, description FROM collections WHERE is_active=1 ORDER BY name").all<{id:string;slug:string;name:string;description:string}>();
    const products = await listProducts(env);
    const collections = await Promise.all((rows.results || []).map(async collection => {
      const links = await env.DB.prepare("SELECT product_id FROM collection_products WHERE collection_id=? ORDER BY sort_order, product_id").bind(collection.id).all<{product_id:string}>();
      const ids = new Set((links.results || []).map(link => link.product_id));
      return { id: collection.id, slug: collection.slug, name: collection.name, description: collection.description, products: products.filter(product => ids.has(product.id)) };
    }));
    return json({ collections });
  }
  if (path === "/api/quick-replies" && request.method === "GET") {
    const rows = await env.DB.prepare("SELECT shortcut, title, message FROM quick_replies WHERE is_active=1 ORDER BY title LIMIT 30").all();
    return json({ quickReplies: rows.results || [] });
  }
  if (path === "/api/admin/store-settings" && request.method === "GET") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    const settings = await env.DB.prepare("SELECT * FROM store_settings WHERE id=1").first<StoreSettingsRow>();
    return json({ settings: settings ? {
      businessName: settings.business_name, tagline: settings.tagline, description: settings.description,
      phone: settings.phone, email: settings.email, address: settings.address, openingHours: settings.opening_hours,
      greetingMessage: settings.greeting_message, awayMessage: settings.away_message, awayEnabled: Boolean(settings.away_enabled)
    } : null });
  }
  if (path === "/api/admin/store-settings" && request.method === "PUT") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    let body: Record<string, unknown>;
    try { body = await request.json() as Record<string, unknown>; } catch { return json({ error: "Invalid JSON body." }, 400); }
    const value = (key: string, max: number, fallback = "") => String(body[key] ?? fallback).trim().slice(0, max);
    const businessName = value("businessName", 100, "MarketMate");
    const tagline = value("tagline", 140, "Your shop, in a chat.");
    const description = value("description", 500);
    const phone = value("phone", 30);
    const email = value("email", 160);
    const address = value("address", 300);
    const openingHours = value("openingHours", 500);
    const greeting = value("greetingMessage", 600, "Hi there! 👋 Welcome. What can I help you find today?");
    const away = value("awayMessage", 600, "Thanks for messaging us. We are currently away, but you can still browse the catalogue and add items to your cart.");
    if (businessName.length < 2 || greeting.length < 2 || away.length < 2) return json({ error: "Business name, greeting and away message are required." }, 400);
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Enter a valid business email." }, 400);
    await env.DB.prepare("UPDATE store_settings SET business_name=?, tagline=?, description=?, phone=?, email=?, address=?, opening_hours=?, greeting_message=?, away_message=?, away_enabled=?, updated_at=? WHERE id=1")
      .bind(businessName, tagline, description, phone, email, address, openingHours, greeting, away, body.awayEnabled === true ? 1 : 0, nowSeconds()).run();
    return json({ ok: true });
  }
  if (path === "/api/admin/quick-replies" && request.method === "GET") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    const rows = await env.DB.prepare("SELECT id, shortcut, title, message, is_active AS isActive FROM quick_replies ORDER BY title").all();
    return json({ quickReplies: rows.results || [] });
  }
  if (path === "/api/admin/quick-replies" && request.method === "POST") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    let body: { shortcut?: string; title?: string; message?: string };
    try { body = await request.json() as typeof body; } catch { return json({ error: "Invalid JSON body." }, 400); }
    const shortcut = String(body.shortcut || "").trim().toLowerCase().replace(/^\//, "");
    const title = String(body.title || "").trim().slice(0, 80);
    const message = String(body.message || "").trim().slice(0, 800);
    if (!/^[a-z0-9_-]{2,30}$/.test(shortcut) || title.length < 2 || message.length < 2) return json({ error: "Enter a shortcut (2–30 letters/numbers), title and reply message." }, 400);
    try {
      await env.DB.prepare("INSERT INTO quick_replies (id, shortcut, title, message, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)")
        .bind(crypto.randomUUID(), shortcut, title, message, nowSeconds(), nowSeconds()).run();
    } catch { return json({ error: "That quick-reply shortcut already exists." }, 409); }
    return json({ ok: true }, 201);
  }
  const quickReplyMatch = path.match(/^\/api\/admin\/quick-replies\/([a-f0-9-]+)$/);
  if (quickReplyMatch && (request.method === "PUT" || request.method === "DELETE")) {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    if (request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM quick_replies WHERE id=?").bind(quickReplyMatch[1]).run();
      return json({ ok: true });
    }
    let body: { shortcut?: string; title?: string; message?: string; isActive?: boolean };
    try { body = await request.json() as typeof body; } catch { return json({ error: "Invalid JSON body." }, 400); }
    const shortcut = String(body.shortcut || "").trim().toLowerCase().replace(/^\//, "");
    const title = String(body.title || "").trim().slice(0, 80);
    const message = String(body.message || "").trim().slice(0, 800);
    if (!/^[a-z0-9_-]{2,30}$/.test(shortcut) || title.length < 2 || message.length < 2) return json({ error: "Enter a valid shortcut, title and reply message." }, 400);
    try {
      await env.DB.prepare("UPDATE quick_replies SET shortcut=?, title=?, message=?, is_active=?, updated_at=? WHERE id=?")
        .bind(shortcut, title, message, body.isActive === false ? 0 : 1, nowSeconds(), quickReplyMatch[1]).run();
    } catch { return json({ error: "That quick-reply shortcut already exists." }, 409); }
    return json({ ok: true });
  }
  if (path === "/api/admin/collections" && request.method === "GET") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    const rows = await env.DB.prepare("SELECT id, slug, name, description, is_active AS isActive FROM collections ORDER BY name").all<{id:string;slug:string;name:string;description:string;isActive:number}>();
    const collections = await Promise.all((rows.results || []).map(async collection => {
      const links = await env.DB.prepare("SELECT product_id FROM collection_products WHERE collection_id=? ORDER BY sort_order").bind(collection.id).all<{product_id:string}>();
      return { ...collection, productIds: (links.results || []).map(link => link.product_id) };
    }));
    return json({ collections });
  }
  if (path === "/api/admin/collections" && request.method === "POST") {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    let body: { name?: string; description?: string; productIds?: string[] };
    try { body = await request.json() as typeof body; } catch { return json({ error: "Invalid JSON body." }, 400); }
    const name = String(body.name || "").trim().slice(0, 80);
    const slug = slugify(name);
    const description = String(body.description || "").trim().slice(0, 500);
    const productIds = Array.isArray(body.productIds) ? [...new Set(body.productIds.filter(id => typeof id === "string" && /^[a-zA-Z0-9-]{1,80}$/.test(id)))].slice(0, 50) : [];
    if (name.length < 2 || !slug) return json({ error: "Enter a collection name." }, 400);
    if (productIds.length) {
      const found = await env.DB.prepare("SELECT COUNT(*) AS count FROM products WHERE id IN (" + productIds.map(() => "?").join(",") + ")").bind(...productIds).first<{count:number}>();
      if (Number(found?.count || 0) !== productIds.length) return json({ error: "One or more selected products could not be found." }, 400);
    }
    const id = crypto.randomUUID();
    try {
      await env.DB.prepare("INSERT INTO collections (id, slug, name, description, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)")
        .bind(id, slug, name, description, nowSeconds(), nowSeconds()).run();
      if (productIds.length) await env.DB.batch(productIds.map((productId, index) => env.DB.prepare("INSERT INTO collection_products (collection_id, product_id, sort_order) VALUES (?, ?, ?)")
        .bind(id, productId, index)));
    } catch { return json({ error: "Could not save collection. Check that its name is unique." }, 409); }
    return json({ ok: true }, 201);
  }
  const collectionMatch = path.match(/^\/api\/admin\/collections\/([a-f0-9-]+)$/);
  if (collectionMatch && (request.method === "PUT" || request.method === "DELETE")) {
    const admin = await requireAdmin(request, env); if (isResponse(admin)) return admin;
    if (request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM collections WHERE id=?").bind(collectionMatch[1]).run();
      return json({ ok: true });
    }
    let body: { name?: string; description?: string; productIds?: string[]; isActive?: boolean };
    try { body = await request.json() as typeof body; } catch { return json({ error: "Invalid JSON body." }, 400); }
    const name = String(body.name || "").trim().slice(0, 80);
    const slug = slugify(name);
    const description = String(body.description || "").trim().slice(0, 500);
    const productIds = Array.isArray(body.productIds) ? [...new Set(body.productIds.filter(id => typeof id === "string" && /^[a-zA-Z0-9-]{1,80}$/.test(id)))].slice(0, 50) : [];
    if (name.length < 2 || !slug) return json({ error: "Enter a collection name." }, 400);
    if (productIds.length) {
      const found = await env.DB.prepare("SELECT COUNT(*) AS count FROM products WHERE id IN (" + productIds.map(() => "?").join(",") + ")").bind(...productIds).first<{count:number}>();
      if (Number(found?.count || 0) !== productIds.length) return json({ error: "One or more selected products could not be found." }, 400);
    }
    try {
      await env.DB.prepare("UPDATE collections SET slug=?, name=?, description=?, is_active=?, updated_at=? WHERE id=?")
        .bind(slug, name, description, body.isActive === false ? 0 : 1, nowSeconds(), collectionMatch[1]).run();
    } catch { return json({ error: "That collection name is already in use." }, 409); }
    await env.DB.prepare("DELETE FROM collection_products WHERE collection_id=?").bind(collectionMatch[1]).run();
    if (productIds.length) await env.DB.batch(productIds.map((productId, index) => env.DB.prepare("INSERT INTO collection_products (collection_id, product_id, sort_order) VALUES (?, ?, ?)")
      .bind(collectionMatch[1], productId, index)));
    return json({ ok: true });
  }
  return null;
}


async function handleWhatsAppWebhook(request: Request, env: StoreEnv, url: URL): Promise<Response> {
  if (request.method === "GET") {
    const mode = url.searchParams.get("hub.mode");
    const token = url.searchParams.get("hub.verify_token");
    const challenge = url.searchParams.get("hub.challenge");
    if (mode === "subscribe" && token && env.WHATSAPP_VERIFY_TOKEN && token === env.WHATSAPP_VERIFY_TOKEN && challenge) {
      return new Response(challenge, { status: 200, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
    }
    return new Response("Webhook verification failed.", { status: 403 });
  }
  if (request.method === "POST") {
    // Meta retries webhook deliveries unless it receives a fast 200 acknowledgement.
    // Signature verification is enabled as soon as the Meta App Secret is configured.
    const rawBody = await request.text();
    if (env.WHATSAPP_APP_SECRET) {
      const signature = request.headers.get("x-hub-signature-256") || "";
      if (!signature.startsWith("sha256=")) return json({ error: "Invalid webhook signature." }, 401);
      const key = await crypto.subtle.importKey("raw", encoder.encode(env.WHATSAPP_APP_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(rawBody)));
      const expected = "sha256=" + Array.from(digest, b => b.toString(16).padStart(2, "0")).join("");
      if (signature.length !== expected.length) return json({ error: "Invalid webhook signature." }, 401);
      let mismatch = 0;
      for (let i = 0; i < expected.length; i++) mismatch |= signature.charCodeAt(i) ^ expected.charCodeAt(i);
      if (mismatch !== 0) return json({ error: "Invalid webhook signature." }, 401);
    }
    let event: unknown;
    try { event = JSON.parse(rawBody); } catch { return json({ error: "Invalid JSON payload." }, 400); }
    // Initial webhook receiver: acknowledge Meta events safely. Message processing and replies
    // will be enabled once the WhatsApp access token and App Secret are configured.
    console.log(JSON.stringify({ message: "WhatsApp webhook received", object: (event as {object?: string})?.object || "unknown" }));
    return new Response("EVENT_RECEIVED", { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } });
  }
  return json({ error: "Method not allowed." }, 405, { allow: "GET, POST" });
}

async function handleChat(request: Request, env: StoreEnv): Promise<Response> {
  let body: { message?: string; history?: Array<{ role?: string; content?: string }> };
  try { body = await request.json() as typeof body; } catch { return json({ error: "Please send a valid message." }, 400); }
  const message = String(body.message || "").trim();
  if (!message || message.length > 500) return json({ error: "Type a message of up to 500 characters." }, 400);

  // Product facts always come from D1; the model may only select real catalogue IDs.
  const catalogue = await listProducts(env);
  const available = catalogue.filter(product => product.inStock && !product.requiresPrescription);
  const catalogueContext = available.slice(0, 60).map(product => ({
    id: product.id, name: product.name, category: product.category,
    description: product.description, priceGHS: product.price,
    stockAvailable: product.stockQuantity
  }));
  const history = (Array.isArray(body.history) ? body.history : [])
    .filter(item => (item.role === "user" || item.role === "assistant") && typeof item.content === "string")
    .slice(-8)
    .map(item => ({ role: item.role as "user" | "assistant", content: String(item.content).slice(0, 1200) }));
  const identity = await cartIdentity(request, env);
  const currentCart = await readCart(env, identity.id);
  const cartContext = currentCart.items.map(item => ({ name: item.product.name, quantity: item.quantity }));

  const settings = await env.DB.prepare("SELECT business_name, description FROM store_settings WHERE id=1").first<{business_name:string;description:string}>();
  const savedReplies = await env.DB.prepare("SELECT shortcut, title, message FROM quick_replies WHERE is_active=1 ORDER BY title LIMIT 30").all<{shortcut:string;title:string;message:string}>();
  const replyContext = (savedReplies.results || []).map(reply => ({ shortcut: reply.shortcut, title: reply.title, message: reply.message }));
  const systemPrompt = [
    "You are the friendly AI shopping assistant for " + (settings?.business_name || "this Ghana-based online shop") + ".",
    "Business description: " + (settings?.description || "Food, clothing and everyday essentials.") + ".",
    "Use relevant saved business quick replies as approved wording for common customer questions, while keeping catalogue facts accurate.",
    "Help customers discover food, clothing and everyday health essentials; understand natural language and ask concise follow-up questions when needed.",
    "Use only the supplied live catalogue for product names, prices, availability and claims. Never invent products, prices, discounts, stock or delivery promises.",
    "Prices are in Ghana cedis (GHS). The store currently supports cash on delivery; customers pay the delivery agent when the order arrives.",
    "Customers can ask you to add an item to their cart. When they clearly request adding or buying a specific catalogue product, set action to {type:'add_to_cart', productId:'exact catalogue ID', quantity:integer}. Only choose a product from the live catalogue. If the product is ambiguous, ask a clarifying question and set action to {type:'none'}. Never claim an item was added; the website will perform the action and confirm it.",
    "Do not claim to have placed an order. To review the cart or check out, customers can say 'show my cart' or 'checkout'; the website will open the cart and delivery form.",
    "Current cart context will be supplied where available. You may answer questions about its contents, but do not alter cart quantities except using the add_to_cart action.",
    "For medicines or symptoms, do not diagnose, prescribe, recommend a treatment or suggest a dosage. You may provide neutral catalogue information for non-prescription health essentials and direct medicine/symptom questions to a licensed pharmacist. Prescription-only products are not available for online checkout.",
    "Be warm, concise and clear. If no catalogue item fits, say so and ask what they are looking for.",
    "Return ONLY valid JSON with exactly this shape: {\"reply\":\"customer-facing answer\",\"productIds\":[\"catalogue-id\"],\"action\":{\"type\":\"none\"}}. For a clear add request, use action {\"type\":\"add_to_cart\",\"productId\":\"exact catalogue-id\",\"quantity\":1}. Select at most 6 productIds from the supplied catalogue. Never return an ID not in the catalogue. Use an empty array if no product cards are useful."
  ].join("\n");
  try {
    const generated = await env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", {
      messages: [
        { role: "system", content: systemPrompt + "\nLive catalogue: " + JSON.stringify(catalogueContext) + "\nCurrent customer cart: " + JSON.stringify(cartContext) },
        ...history,
        { role: "user", content: message }
      ],
      max_tokens: 550,
      temperature: 0.25
    }) as { response?: unknown; choices?: Array<{ message?: { content?: unknown } }> };
    const responseValue = generated.response;
    const raw = (typeof responseValue === "string" ? responseValue
      : responseValue && typeof responseValue === "object" ? JSON.stringify(responseValue)
      : typeof generated.choices?.[0]?.message?.content === "string" ? generated.choices[0].message.content
      : "").trim();
    const cleaned = raw.replace(/^\x60{3}(?:json)?\s*/i, "").replace(/\s*\x60{3}$/, "");
    let parsed: { reply?: string; productIds?: string[]; action?: { type?: string; productId?: string; quantity?: number } } = {};
    if (responseValue && typeof responseValue === "object" && !Array.isArray(responseValue)) {
      parsed = responseValue as { reply?: string; productIds?: string[] };
    } else {
      try { parsed = JSON.parse(cleaned) as typeof parsed; } catch { /* use a safe plain-text fallback below */ }
    }
    const reply = typeof parsed.reply === "string" && parsed.reply.trim()
      ? parsed.reply.trim().slice(0, 1600)
      : raw.slice(0, 1600) || "Sorry, I couldn’t prepare an answer just now. Please try again.";
    const selectedIds = Array.isArray(parsed.productIds) ? parsed.productIds.slice(0, 6) : [];
    const selected = new Set(selectedIds.filter(id => typeof id === "string"));
    const products = available.filter(product => selected.has(product.id)).slice(0, 6);
    const requestedAction = parsed.action;
    let action: { type: "add_to_cart"; productId: string; quantity: number } | { type: "none" } = { type: "none" };
    if (requestedAction?.type === "add_to_cart" && typeof requestedAction.productId === "string") {
      const target = available.find(product => product.id === requestedAction.productId);
      const quantity = Number(requestedAction.quantity ?? 1);
      if (target && Number.isInteger(quantity) && quantity >= 1 && quantity <= 99) {
        action = { type: "add_to_cart", productId: target.id, quantity };
        if (!products.some(product => product.id === target.id)) products.unshift(target);
      }
    }
    return json({ reply, products: products.slice(0, 6), action, ai: true }, 200,
      identity.setCookie ? { "set-cookie": identity.setCookie } : {});
  } catch (error) {
    console.error(JSON.stringify({ message: "Workers AI chat request failed", error: error instanceof Error ? error.message : String(error) }));
    return json({ error: "The AI shopping assistant is temporarily unavailable. Please try again shortly." }, 503);
  }
}

export default {
  async fetch(request: Request, env: StoreEnv): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/health") return json({ ok: true, app: "marketmate", stage: "cash-on-delivery" });
      if (url.pathname === "/api/whatsapp/webhook") return handleWhatsAppWebhook(request, env, url);
      const auth = await handleAuth(request, env, url.pathname);
      if (auth) return auth;
      const media = await handleMedia(request, env, url.pathname);
      if (media) return media;
      if (url.pathname === "/api/admin/uploads" && request.method === "POST") return handleUploads(request, env);
      const businessTools = await handleBusinessTools(request, env, url.pathname);
      if (businessTools) return businessTools;
      const categories = await handleCategories(request, env, url.pathname);
      if (categories) return categories;
      const adminOrders = await handleAdminOrders(request, env, url.pathname);
      if (adminOrders) return adminOrders;
      const cart = await handleCart(request, env, url.pathname);
      if (cart) return cart;
      const checkout = await handleCheckout(request, env);
      if (checkout) return checkout;
      const products = await handleProducts(request, env, url.pathname);
      if (products) return products;
      if (url.pathname === "/api/chat" && request.method === "POST") return handleChat(request, env);
      if (url.pathname.startsWith("/api/")) return json({ error: "Not found." }, 404);
      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error(JSON.stringify({ message: "request failed", path: url.pathname, error: error instanceof Error ? error.message : String(error) }));
      return json({ error: "Something went wrong. Please try again." }, 500);
    }
  }
};
