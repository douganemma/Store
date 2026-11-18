PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS store_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  business_name TEXT NOT NULL DEFAULT 'MarketMate',
  tagline TEXT NOT NULL DEFAULT 'Your shop, in a chat.',
  description TEXT NOT NULL DEFAULT 'Food, clothing and everyday essentials.',
  phone TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL DEFAULT '',
  opening_hours TEXT NOT NULL DEFAULT '',
  greeting_message TEXT NOT NULL DEFAULT 'Hi there! 👋 Welcome. What can I help you find today?',
  away_message TEXT NOT NULL DEFAULT 'Thanks for messaging us. We are currently away, but you can still browse the catalogue and add items to your cart.',
  away_enabled INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO store_settings (id, updated_at) VALUES (1, unixepoch());

CREATE TABLE IF NOT EXISTS quick_replies (
  id TEXT PRIMARY KEY,
  shortcut TEXT NOT NULL UNIQUE COLLATE NOCASE,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS collections (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS collection_products (
  collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
  product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  sort_order INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (collection_id, product_id)
);

CREATE INDEX IF NOT EXISTS idx_collections_active ON collections(is_active, name);
CREATE INDEX IF NOT EXISTS idx_collection_products_order ON collection_products(collection_id, sort_order);
