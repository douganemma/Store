PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS carts (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cart_items (
  cart_id TEXT NOT NULL REFERENCES carts(id) ON DELETE CASCADE,
  product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  quantity INTEGER NOT NULL CHECK(quantity > 0 AND quantity <= 99),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(cart_id, product_id)
);
CREATE INDEX IF NOT EXISTS idx_carts_expiry ON carts(expires_at);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  order_number TEXT NOT NULL UNIQUE,
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  delivery_address TEXT NOT NULL,
  delivery_notes TEXT NOT NULL DEFAULT '',
  subtotal_pesewas INTEGER NOT NULL,
  delivery_fee_pesewas INTEGER NOT NULL DEFAULT 0,
  total_pesewas INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'GHS',
  payment_method TEXT NOT NULL DEFAULT 'cash_on_delivery',
  payment_status TEXT NOT NULL DEFAULT 'pay_on_delivery',
  order_status TEXT NOT NULL DEFAULT 'pending_confirmation',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS order_items (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id TEXT,
  product_name TEXT NOT NULL,
  sku TEXT NOT NULL,
  unit_price_pesewas INTEGER NOT NULL,
  quantity INTEGER NOT NULL,
  line_total_pesewas INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(order_status);
