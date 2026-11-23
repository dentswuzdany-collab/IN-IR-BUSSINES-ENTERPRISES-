
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const app = express();

app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));

// NEON DATABASE CONNECTION
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ADMINISTRATOR CONFIGURATION
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SECRET = process.env.SESSION_SECRET;

// Generate a bcrypt hash from the Render environment password.
const PASSWORD_HASH_PROMISE = ADMIN_PASSWORD
  ? bcrypt.hash(ADMIN_PASSWORD, 12)
  : null;

if (!process.env.DATABASE_URL || !ADMIN_PASSWORD || !SECRET) {
  throw new Error(
    "Set DATABASE_URL, ADMIN_PASSWORD and SESSION_SECRET in Render."
  );
}

// SIGN ADMINISTRATOR SESSION
function sign(value) {
  return crypto
    .createHmac("sha256", SECRET)
    .update(value)
    .digest("hex");
}

// VERIFY ADMINISTRATOR SESSION
function getAdminSession(req) {
  const cookieHeader = req.headers.cookie || "";

  const cookie = cookieHeader
    .split(";")
    .map(item => item.trim())
    .find(item => item.startsWith("inair_admin="));

  if (!cookie) return null;

  const token = cookie.substring("inair_admin=".length);
  const parts = token.split(".");

  if (parts.length !== 2) return null;

  const expected = sign(parts[0]);
  const a = Buffer.from(parts[1]);
  const b = Buffer.from(expected);

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return null;
  }

  try {
    const data = JSON.parse(
      Buffer.from(parts[0], "base64url").toString()
    );

    if (data.admin !== true || data.exp <= Date.now()) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

function adminOnly(req, res, next) {
  if (!getAdminSession(req)) {
    return res.status(401).json({
      error: "Administrator login required."
    });
  }

  next();
}

// RATE LIMITING
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 40,
  standardHeaders: true,
  legacyHeaders: false
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false
});

// DATABASE SETUP
async function setup() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      category VARCHAR(100),
      cost_price NUMERIC(14,2) NOT NULL,
      selling_price NUMERIC(14,2) NOT NULL,
      stock_quantity INTEGER NOT NULL DEFAULT 0,
      low_stock_level INTEGER NOT NULL DEFAULT 5,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sales (
      id BIGSERIAL PRIMARY KEY,
      product_id INTEGER REFERENCES products(id),
      product_name VARCHAR(150) NOT NULL,
      quantity INTEGER NOT NULL,
      unit_price NUMERIC(14,2) NOT NULL,
      unit_cost NUMERIC(14,2) NOT NULL,
      total_amount NUMERIC(14,2) NOT NULL,
      cost_total NUMERIC(14,2) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS expenses (
      id BIGSERIAL PRIMARY KEY,
      description VARCHAR(160) NOT NULL,
      category VARCHAR(100),
      amount NUMERIC(14,2) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log("IN@IR database connected.");
}

// ADMIN LOGIN
app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    if (
      typeof req.body.password !== "string" ||
      req.body.password.length > 200
    ) {
      return res.status(400).json({
        error: "Invalid password."
      });
    }

    const passwordHash = await PASSWORD_HASH_PROMISE;

    const valid = await bcrypt.compare(
      req.body.password,
      passwordHash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Incorrect password."
      });
    }

    const payload = Buffer.from(
      JSON.stringify({
        admin: true,
        exp: Date.now() + 8 * 60 * 60 * 1000
      })
    ).toString("base64url");

    const token = payload + "." + sign(payload);

    res.setHeader(
      "Set-Cookie",
      `inair_admin=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`
    );

    res.json({ success: true });

  } catch (e) {
    console.error("Login error:", e);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

// ADMIN LOGOUT
app.post("/api/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "inair_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
  );

  res.json({ success: true });
});

// CHECK ADMIN SESSION
app.get("/api/session", (req, res) => {
  res.json({
    admin: !!getAdminSession(req)
  });
});

// PUBLIC PRODUCT LIST
app.get("/api/products", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT
        id,
        name,
        category,
        selling_price,
        stock_quantity
      FROM products
      ORDER BY name
    `);

    res.json(r.rows);

  } catch (e) {
    console.error("Products error:", e);

    res.status(500).json({
      error: "Unable to load products."
    });
  }
});

// ADMIN INVENTORY
app.get("/api/admin/products", adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM products ORDER BY name"
    );

    res.json(r.rows);

  } catch (e) {
    console.error("Inventory error:", e);

    res.status(500).json({
      error: "Unable to load inventory."
    });
  }
});

// ADD PRODUCT
app.post("/api/admin/products", adminOnly, async (req, res) => {
  try {
    const {
      name,
      category,
      cost_price,
      selling_price,
      stock_quantity,
      low_stock_level
    } = req.body;

    if (
      typeof name !== "string" ||
      !name.trim() ||
      name.length > 150 ||
      !Number.isFinite(Number(cost_price)) ||
      Number(cost_price) < 0 ||
      !Number.isFinite(Number(selling_price)) ||
      Number(selling_price) < 0 ||
      !Number.isInteger(Number(stock_quantity)) ||
      Number(stock_quantity) < 0 ||
      !Number.isInteger(Number(low_stock_level)) ||
      Number(low_stock_level) < 0
    ) {
      return res.status(400).json({
        error: "Check product information."
      });
    }

    const r = await pool.query(
      `INSERT INTO products
       (name, category, cost_price, selling_price,
        stock_quantity, low_stock_level)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [
        name.trim(),
        String(category || "").slice(0, 100),
        cost_price,
        selling_price,
        stock_quantity,
        low_stock_level
      ]
    );

    res.json(r.rows[0]);

  } catch (e) {
    console.error("Add product error:", e);

    res.status(500).json({
      error: "Unable to add product."
    });
  }
});

// EDIT PRODUCT
app.put("/api/admin/products/:id", adminOnly, async (req, res) => {
  try {
    const {
      name,
      category,
      cost_price,
      selling_price,
      stock_quantity,
      low_stock_level
    } = req.body;

    const id = Number(req.params.id);

    if (
      !Number.isInteger(id) ||
      id < 1 ||
      typeof name !== "string" ||
      !name.trim() ||
      name.length > 150 ||
      !Number.isFinite(Number(cost_price)) ||
      Number(cost_price) < 0 ||
      !Number.isFinite(Number(selling_price)) ||
      Number(selling_price) < 0 ||
      !Number.isInteger(Number(stock_quantity)) ||
      Number(stock_quantity) < 0 ||
      !Number.isInteger(Number(low_stock_level)) ||
      Number(low_stock_level) < 0
    ) {
      return res.status(400).json({
        error: "Invalid product information."
      });
    }

    const r = await pool.query(
      `UPDATE products
       SET name=$1,
           category=$2,
           cost_price=$3,
           selling_price=$4,
           stock_quantity=$5,
           low_stock_level=$6
       WHERE id=$7
       RETURNING *`,
      [
        name.trim(),
        String(category || "").slice(0, 100),
        cost_price,
        selling_price,
        stock_quantity,
        low_stock_level,
        id
      ]
    );

    if (!r.rowCount) {
      return res.status(404).json({
        error: "Product not found."
      });
    }

    res.json(r.rows[0]);

  } catch (e) {
    console.error("Edit product error:", e);

    res.status(500).json({
      error: "Unable to update product."
    });
  }
});

// RECORD SALE - STAFF ACCESS
app.post("/api/sales", limiter, async (req, res) => {
  const { product_id, quantity } = req.body;

  const productId = Number(product_id);
  const qty = Number(quantity);

  if (
    !Number.isInteger(productId) ||
    productId < 1 ||
    !Number.isInteger(qty) ||
    qty < 1 ||
    qty > 100000
  ) {
    return res.status(400).json({
      error: "Invalid sale details."
    });
  }

  let client;

  try {
    client = await pool.connect();

    await client.query("BEGIN");

    const p = await client.query(
      "SELECT * FROM products WHERE id=$1 FOR UPDATE",
      [productId]
    );

    if (!p.rowCount) {
      throw new Error("Product not found.");
    }

    const product = p.rows[0];

    if (Number(product.stock_quantity) < qty) {
      throw new Error(
        "Insufficient stock. Available: " +
        product.stock_quantity
      );
    }

    const total = Number(product.selling_price) * qty;
    const cost = Number(product.cost_price) * qty;

    await client.query(
      `UPDATE products
       SET stock_quantity = stock_quantity - $1
       WHERE id = $2`,
      [qty, productId]
    );

    await client.query(
      `INSERT INTO sales
       (product_id, product_name, quantity, unit_price,
        unit_cost, total_amount, cost_total)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [
        productId,
        product.name,
        qty,
        product.selling_price,
        product.cost_price,
        total,
        cost
      ]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Sale recorded successfully."
    });

  } catch (e) {
    if (client) {
      await client.query("ROLLBACK").catch(() => {});
    }

    console.error("Sale error:", e);

    res.status(400).json({
      error: e.message
    });

  } finally {
    if (client) client.release();
  }
});

// RECORD EXPENSE - STAFF ACCESS
app.post("/api/expenses", limiter, async (req, res) => {
  try {
    const { description, category, amount } = req.body;

    const value = Number(amount);

    if (
      typeof description !== "string" ||
      !description.trim() ||
      description.length > 160 ||
      !Number.isFinite(value) ||
      value <= 0 ||
      value > 100000000000
    ) {
      return res.status(400).json({
        error: "Invalid expense details."
      });
    }

    await pool.query(
      `INSERT INTO expenses
       (description, category, amount)
       VALUES ($1,$2,$3)`,
      [
        description.trim(),
        String(category || "Other").slice(0, 100),
        value
      ]
    );

    res.json({
      success: true,
      message: "Expense recorded successfully."
    });

  } catch (e) {
    console.error("Expense error:", e);

    res.status(500).json({
      error: "Unable to record expense."
    });
  }
});

// ADMIN SALES HISTORY
app.get("/api/admin/sales", adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM sales ORDER BY created_at DESC"
    );

    res.json(r.rows);

  } catch (e) {
    console.error("Sales history error:", e);

    res.status(500).json({
      error: "Unable to load sales history."
    });
  }
});

// ADMIN EXPENSE HISTORY
app.get("/api/admin/expenses", adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM expenses ORDER BY created_at DESC"
    );

    res.json(r.rows);

  } catch (e) {
    console.error("Expense history error:", e);

    res.status(500).json({
      error: "Unable to load expense history."
    });
  }
});

// ADMIN FINANCIAL REPORT
app.get("/api/admin/summary", adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT
        COALESCE(
          (SELECT SUM(total_amount) FROM sales), 0
        ) AS revenue,

        COALESCE(
          (SELECT SUM(cost_total) FROM sales), 0
        ) AS cost,

        COALESCE(
          (SELECT SUM(amount) FROM expenses), 0
        ) AS expenses,

        COALESCE(
          (SELECT SUM(stock_quantity) FROM products), 0
        ) AS stock,

        (SELECT COUNT(*) FROM products) AS product_count,

        (SELECT COUNT(*) FROM sales) AS sales_count
    `);

    const d = r.rows[0];

    const gross = Number(d.revenue) - Number(d.cost);

    res.json({
      ...d,
      gross_profit: gross,
      net_profit: gross - Number(d.expenses)
    });

  } catch (e) {
    console.error("Financial summary error:", e);

    res.status(500).json({
      error: "Unable to load financial summary."
    });
  }
});

// WEBSITE FILES
app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

// START SERVER
const PORT = process.env.PORT || 3000;

setup()
  .then(() => {
    app.listen(PORT, () => {
      console.log("IN@IR BUSINESS ENTERPRISES is running.");
    });
  })
  .catch(e => {
    console.error("Server startup failed:", e);
    process.exit(1);
  });
