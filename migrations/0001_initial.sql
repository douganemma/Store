PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS categories (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  sku TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  category_slug TEXT NOT NULL REFERENCES categories(slug),
  description TEXT NOT NULL DEFAULT '',
  price_pesewas INTEGER NOT NULL CHECK (price_pesewas >= 0),
  stock_quantity INTEGER NOT NULL DEFAULT 0 CHECK (stock_quantity >= 0),
  is_active INTEGER NOT NULL DEFAULT 1,
  image_key TEXT,
  attributes_json TEXT NOT NULL DEFAULT '{}',
  requires_prescription INTEGER NOT NULL DEFAULT 0,
  batch_number TEXT,
  expiry_date TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_products_category ON products(category_slug, is_active);
CREATE INDEX IF NOT EXISTS idx_products_name ON products(name);

CREATE TABLE IF NOT EXISTS admins (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry ON admin_sessions(expires_at);
CREATE TABLE IF NOT EXISTS login_attempts (
  id TEXT PRIMARY KEY,
  ip_hash TEXT NOT NULL,
  attempted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_hash, attempted_at);

INSERT OR IGNORE INTO categories (id, slug, name, description, is_active, created_at) VALUES
  ('cat-food', 'food', 'Food & groceries', 'Freshly prepared food and grocery items.', 1, unixepoch()),
  ('cat-clothing', 'clothing', 'Clothing', 'Clothing, footwear and accessories.', 1, unixepoch()),
  ('cat-medicine', 'medicine', 'Health essentials', 'Health products subject to applicable pharmacy and regulatory controls.', 1, unixepoch());

INSERT OR IGNORE INTO products
(id, sku, name, category_slug, description, price_pesewas, stock_quantity, is_active, attributes_json, requires_prescription, created_at, updated_at)
VALUES
('food-001', 'FOOD-001', 'Jollof Rice with Chicken', 'food', 'A freshly prepared serving. Ask about available portions before ordering.', 6500, 20, 1, '{"portion":"single"}', 0, unixepoch(), unixepoch()),
('clothes-001', 'CLOTH-001', 'Classic Cotton T-Shirt', 'clothing', 'Everyday cotton T-shirt. Confirm available sizes and colours before ordering.', 9000, 15, 1, '{"sizes":["S","M","L","XL"],"colours":["Black","White"]}', 0, unixepoch(), unixepoch()),
('medicine-001', 'HEALTH-001', 'First Aid Essentials Kit', 'medicine', 'A general first-aid kit. Ask a licensed pharmacist about medicines and treatment choices.', 12000, 10, 1, '{}', 0, unixepoch(), unixepoch());
