-- Cloudflare D1 schema (SQLite)
-- Apply with: wrangler d1 execute nexus-portal-db --file=src/schema.sql

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  fullName TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'disabled')),
  leaveCredits REAL DEFAULT 20.0,
  must_change_password INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pending_users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  fullName TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userEmail TEXT NOT NULL,
  userName TEXT NOT NULL,
  type TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  image TEXT,
  location TEXT,
  todo TEXT,
  progress TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS holiday_requests (
  id TEXT PRIMARY KEY,
  userEmail TEXT NOT NULL,
  userName TEXT NOT NULL,
  holidayName TEXT NOT NULL,
  holidayDate TEXT NOT NULL,
  details TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied')),
  timestamp TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS leave_applications (
  id TEXT PRIMARY KEY,
  userEmail TEXT NOT NULL,
  userName TEXT NOT NULL,
  leaveType TEXT NOT NULL,
  startDate TEXT NOT NULL,
  endDate TEXT NOT NULL,
  dayType TEXT NOT NULL DEFAULT 'whole' CHECK(dayType IN ('whole', 'half')),
  halfDayShift TEXT CHECK(halfDayShift IN ('morning', 'afternoon')),
  payType TEXT NOT NULL DEFAULT 'withPay' CHECK(payType IN ('withPay', 'withoutPay')),
  details TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied')),
  timestamp TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS password_reset_requests (
  id TEXT PRIMARY KEY,
  userEmail TEXT NOT NULL,
  userName TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied')),
  tempPassword TEXT,
  timestamp TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_prr_userEmail ON password_reset_requests(userEmail);
