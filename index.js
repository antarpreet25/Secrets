// index.js
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const path = require("path");
const validator = require("validator");
const User = require("./models/User");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// ---------- Middleware ----------
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// ---------- DB ----------
const mongoURI =
  process.env.MONGO_URI || "mongodb://127.0.0.1:27017/secretsApp";
mongoose
  .connect(mongoURI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ DB error:", err));

// ---------- Auth Middleware ----------
const isAuthenticated = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, name, email }
    next();
  } catch {
    res.clearCookie("token", cookieClearOptions());
    return res.redirect("/login");
  }
};

// Cookie options helpers
const cookieOptions = () => ({
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production", // Render uses HTTPS → true in prod
  maxAge: 24 * 60 * 60 * 1000, // 1 day
});
const cookieClearOptions = () => ({
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
});

// ---------- Routes ----------
app.get("/", (req, res) => res.render("home"));

app.get("/register", (req, res) => res.render("register", { error: "" }));

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  // Validate
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;
  if (!name?.trim()) {
    return res.render("register", { error: "Name is required." });
  }
  if (!validator.isEmail(email || "")) {
    return res.render("register", { error: "Invalid email format." });
  }
  if (!passwordRegex.test(password || "")) {
    return res.render("register", {
      error:
        "Password must include lowercase, uppercase, a number, and be at least 6 characters.",
    });
  }

  try {
    const existing = await User.findOne({ email });
    if (existing)
      return res.render("register", { error: "User already exists." });

    const user = new User({ name, email, password });
    await user.save();
    return res.redirect("/login");
  } catch (err) {
    console.error(err);
    return res.render("register", { error: "Error during registration." });
  }
});

app.get("/login", (req, res) => res.render("login", { error: "" }));

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!validator.isEmail(email || "")) {
    return res.render("login", { error: "Invalid email format." });
  }
  if (!password) {
    return res.render("login", { error: "Password is required." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.render("login", { error: "Incorrect email or password." });
    }

    const token = jwt.sign(
      { id: user._id.toString(), name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.cookie("token", token, cookieOptions());
    return res.redirect("/secret");
  } catch (err) {
    console.error(err);
    return res.render("login", { error: "Login failed." });
  }
});

app.get("/secret", isAuthenticated, (req, res) => {
  res.render("secret", { user: req.user });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token", cookieClearOptions());
  return res.redirect("/login");
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`🚀 Server started on http://localhost:${PORT}`);
});
