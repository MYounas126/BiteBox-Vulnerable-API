// In-memory SQLite. Every restart reseeds the same fake data.
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';

export let db;

export function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(pw, salt, 32).toString('hex')}`;
}

export function checkPassword(pw, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const a = Buffer.from(hash, 'hex');
  const b = crypto.scryptSync(pw, salt, 32);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const SCHEMA = `
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', wallet_balance REAL NOT NULL DEFAULT 50,
  suspended INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE addresses (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, label TEXT, line1 TEXT, city TEXT);
CREATE TABLE restaurants (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, name TEXT NOT NULL, cuisine TEXT,
  city TEXT, rating REAL DEFAULT 4.0, webhook_url TEXT, courier_url TEXT NOT NULL DEFAULT 'internal', approved INTEGER DEFAULT 1);
CREATE TABLE menu_items (id INTEGER PRIMARY KEY, restaurant_id INTEGER NOT NULL, name TEXT NOT NULL, price REAL NOT NULL,
  available INTEGER NOT NULL DEFAULT 1);
CREATE TABLE reviews (id INTEGER PRIMARY KEY, restaurant_id INTEGER NOT NULL, user_id INTEGER NOT NULL, rating INTEGER,
  comment TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL, restaurant_id INTEGER NOT NULL,
  address_id INTEGER, status TEXT NOT NULL DEFAULT 'pending', subtotal REAL NOT NULL, discount REAL NOT NULL DEFAULT 0,
  delivery_fee REAL NOT NULL DEFAULT 0, quoted INTEGER NOT NULL DEFAULT 0, coupon_code TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE order_items (id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL, menu_item_id INTEGER NOT NULL,
  qty INTEGER NOT NULL, unit_price REAL NOT NULL);
CREATE TABLE coupons (code TEXT PRIMARY KEY, percent INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE redemptions (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, code TEXT NOT NULL, order_id INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE wallet_tx (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, amount REAL NOT NULL, reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE refresh_tokens (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL);
CREATE TABLE otps (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, code TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  used INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL);
`;

const CUISINES = ['Pakistani', 'Chinese', 'Italian', 'Thai', 'Lebanese', 'South Indian', 'Burgers', 'Salads'];
const DISHES = {
  Pakistani: [['Chicken Karahi', 14], ['Beef Nihari', 13], ['Seekh Kebab', 9], ['Garlic Naan', 2]],
  Chinese: [['Kung Pao Chicken', 12], ['Egg Fried Rice', 7], ['Hot and Sour Soup', 5]],
  Italian: [['Margherita Pizza', 11], ['Penne Arrabbiata', 10], ['Tiramisu', 6]],
  Thai: [['Green Curry', 12], ['Pad Thai', 11], ['Mango Sticky Rice', 6]],
  Lebanese: [['Chicken Shawarma', 8], ['Falafel Plate', 9], ['Hummus', 5]],
  'South Indian': [['Masala Dosa', 8], ['Idli Sambar', 6], ['Filter Coffee', 3]],
  Burgers: [['Smash Burger', 10], ['Loaded Fries', 6], ['Milkshake', 5]],
  Salads: [['Greek Salad', 9], ['Quinoa Bowl', 11], ['Lemonade', 3]],
};

export function initDb() {
  db = new DatabaseSync(':memory:');
  db.exec(SCHEMA);
  seed();
  return db;
}

function seed() {
  const addUser = db.prepare('INSERT INTO users (name, email, phone, password_hash, role, wallet_balance) VALUES (?, ?, ?, ?, ?, ?)');
  // Seeded passwords are random and never printed: trainees work with accounts they register.
  const pw = () => hashPassword(crypto.randomBytes(18).toString('base64url'));
  addUser.run('Platform Admin', 'admin@bitebox.test', '+920000000001', pw(), 'admin', 0);
  const people = [
    ['Ayesha Rahman', 'ayesha.rahman@mail.test', '+920000000101'],
    ['Bilal Qureshi', 'bilal.qureshi@mail.test', '+920000000102'],
    ['Sana Mirza', 'sana.mirza@mail.test', '+920000000103'],
  ];
  for (const [n, e, p] of people) addUser.run(n, e, p, pw(), 'customer', 50);
  const merchants = [
    ['Karahi Corner', 'Pakistani', 'Karachi'], ['Noodle Nook', 'Chinese', 'Lahore'], ['Slice Society', 'Italian', 'Karachi'],
    ['Lemongrass Lane', 'Thai', 'Islamabad'], ['Cedar Grill', 'Lebanese', 'Lahore'], ['Daily Dosa', 'South Indian', 'Karachi'],
  ];
  const addRest = db.prepare('INSERT INTO restaurants (owner_id, name, cuisine, city, rating) VALUES (?, ?, ?, ?, ?)');
  const addItem = db.prepare('INSERT INTO menu_items (restaurant_id, name, price) VALUES (?, ?, ?)');
  merchants.forEach(([name, cuisine, city], i) => {
    const slug = name.toLowerCase().replace(/[^a-z]+/g, '.');
    const owner = addUser.run(`${name} Owner`, `owner@${slug}test`, `+92000000020${i}`, pw(), 'merchant', 0).lastInsertRowid;
    const rid = addRest.run(owner, name, cuisine, city, 4 + (i % 10) / 10).lastInsertRowid;
    for (const [dish, price] of DISHES[cuisine]) addItem.run(rid, dish, price);
  });
  // A large directory of listed kitchens, so list endpoints have something to page through.
  const bulk = addUser.run('Directory Import', 'import@bitebox.test', null, pw(), 'merchant', 0).lastInsertRowid;
  const cities = ['Karachi', 'Lahore', 'Islamabad', 'Peshawar', 'Multan'];
  db.exec('BEGIN');
  for (let i = 1; i <= 1500; i++) {
    const c = CUISINES[i % CUISINES.length];
    addRest.run(bulk, `${c} Kitchen ${i}`, c, cities[i % cities.length], 3 + (i % 20) / 10);
  }
  db.exec('COMMIT');

  const addOrder = db.prepare('INSERT INTO orders (customer_id, restaurant_id, status, subtotal) VALUES (?, ?, ?, ?)');
  const addOI = db.prepare('INSERT INTO order_items (order_id, menu_item_id, qty, unit_price) VALUES (?, ?, ?, ?)');
  const items = db.prepare('SELECT * FROM menu_items WHERE restaurant_id = ?');
  [[2, 1], [3, 2], [4, 3], [2, 4]].forEach(([cust, rest], i) => {
    const its = items.all(rest).slice(0, 2);
    const subtotal = its.reduce((s, it) => s + it.price, 0);
    const oid = addOrder.run(cust, rest, i % 2 ? 'delivered' : 'paid', subtotal).lastInsertRowid;
    for (const it of its) addOI.run(oid, it.id, 1, it.price);
  });
  db.prepare('INSERT INTO addresses (user_id, label, line1, city) VALUES (?, ?, ?, ?)').run(2, 'Home', '12 Example Street', 'Karachi');
  const addReview = db.prepare('INSERT INTO reviews (restaurant_id, user_id, rating, comment) VALUES (?, ?, ?, ?)');
  addReview.run(1, 2, 5, 'Best karahi in town.');
  addReview.run(1, 3, 4, 'Good, but delivery was slow.');
  addReview.run(2, 4, 3, 'Noodles were cold.');
  const addCoupon = db.prepare('INSERT INTO coupons (code, percent) VALUES (?, ?)');
  addCoupon.run('WELCOME10', 10);
  addCoupon.run('FEAST20', 20);
}

export const publicUser = (u) => u && ({
  id: u.id, name: u.name, email: u.email, phone: u.phone, role: u.role, walletBalance: u.wallet_balance,
});
