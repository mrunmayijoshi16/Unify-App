import express from "express";
import mysql from "mysql2/promise"; // Use promise-based mysql2
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { authenticateToken } from "./middleware/auth.js";

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// MySQL connection pool
const db = await mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

app.get("/dashboard", authenticateToken, (req, res) => {
  res.json({
    message: "Welcome to your dashboard 🎓",
  });
});

// SIGNUP with student verification
app.post("/signup", async (req, res) => {
  try {
    const { prn, password, name, course, year, interests } = req.body;
    console.log("Signup request body:", req.body);

    // ✅ Validate PRN: must be exactly 12 digits
    if (!/^\d{12}$/.test(String(prn))) {
      return res.status(400).json({ message: "PRN must be exactly 12 digits" });
    }

    // 1️⃣ Check if student exists in the official students table
    const [validStudent] = await db.query(
      "SELECT * FROM students WHERE prn = ? AND name = ? AND course = ? AND year = ?",
      [prn, name, course, year]
    );

    if (validStudent.length === 0) {
      return res.status(400).json({
        message: "Invalid student details ❌. Please enter correct information.",
      });
    }

    // 2️⃣ Check if user already signed up
    const [existingUser] = await db.query("SELECT * FROM users WHERE prn = ?", [
      prn,
    ]);

    if (existingUser.length > 0) {
      return res.status(400).json({ message: "User already registered. Please login to continue." });
    }

    // 3️⃣ Hash password and insert into users table
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query(
      "INSERT INTO users (prn, password, name, course, year, interests) VALUES (?, ?, ?, ?, ?, ?)",
      [prn, hashedPassword, name, course, year, interests]
    );

    res.json({ message: "User registered successfully ✅" });
  } catch (err) {
    console.error("❌ Signup Error:", err);
    res.status(500).json({ message: "Server error during signup" });
  }
});


// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { prn, password } = req.body;

    const [rows] = await db.query("SELECT * FROM users WHERE prn = ?", [prn]);
    if (rows.length === 0) {
      return res.status(400).json({ message: "User not registered. Please signup first." });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      { id: user.id, prn: user.prn },
      process.env.JWT_SECRET || "mysecretkey",
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        prn: user.prn,
        name: user.name,
        course: user.course,
        year: user.year,
        interests: user.interests,
      },
    });
  } catch (err) {
    console.error("❌ Login Error:", err);
    res.status(500).json({ message: "Server error during login" });
  }
});

// MARKETPLACE ROUTES (Protected)
// Add item
app.post("/marketplace", authenticateToken, async (req, res) => {
  try {
    const { title, description, price ,image_url} = req.body;
    const sellerId = req.user.id;

    if (!title || !price) {
      return res.status(400).json({ message: "Title and price are required" });
    }

    await db.query(
      "INSERT INTO marketplace_items (seller_id, title, description, price, image_url) VALUES (?, ?, ?, ?, ?)",
      [req.user.id, title, description, price, image_url || null]
    );

    res.json({ message: "Item added successfully ✅" });
  } catch (err) {
    console.error("❌ Marketplace Add Error:", err.message);
    res.status(500).json({ message: "Server error while adding item" });
  }
});

// Get all items
app.get("/marketplace", authenticateToken, async (req, res) => {
  try {
    const [items] = await db.query(
      `SELECT m.id, m.title, m.description, m.price, 
              u.name AS seller, u.id AS seller_id
       FROM marketplace_items m
       JOIN users u ON m.seller_id = u.id`
    );
    res.json(items);
  } catch (err) {
    console.error("❌ Marketplace Fetch Error:", err);
    res.status(500).json({ message: "Server error while fetching items" });
  }
});

// Delete item (only owner can delete)
app.delete("/marketplace/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Verify item belongs to user
    const [item] = await db.query("SELECT * FROM marketplace WHERE id = ?", [id]);
    if (item.length === 0) {
      return res.status(404).json({ message: "Item not found ❌" });
    }

    if (item[0].user_id !== req.user.id) {
      return res.status(403).json({ message: "Unauthorized ❌" });
    }

    await db.query("DELETE FROM marketplace WHERE id = ?", [id]);
    res.json({ message: "Item deleted successfully ✅" });
  } catch (err) {
    console.error("❌ Marketplace Delete Error:", err);
    res.status(500).json({ message: "Server error while deleting item" });
  }
});

// Fetch user profile by ID
app.get("/users/:id", authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, prn, name, course, year, interests FROM users WHERE id = ?",
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error("❌ Profile Fetch Error:", err);
    res.status(500).json({ message: "Server error while fetching profile" });
  }
});



// Start server
app.listen(5000, () => {
  console.log("🚀 Server running on port 5000");
});
