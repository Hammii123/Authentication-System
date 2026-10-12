import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "../config/db.js";

// How much work bcrypt does to hash a password. Higher = safer but slower.
const SALT_ROUNDS = 12;

// A fake hash used when the email is not found at login (explained in login below)
const DUMMY_HASH = bcrypt.hashSync("dummy-password-for-timing", SALT_ROUNDS);

// Email format rules, written as a pattern:
// - before the @ : letters/numbers, with single . _ % + - between them (never at the start, end, or doubled)
// - after the @  : one or more domain parts (letters, numbers, - inside), each followed by a dot
// - the ending (like com, pk, co.uk) must be LETTERS only, 2 to 24 long, so "1223@123.3214" is rejected
const EMAIL_REGEX =
  /^[a-z0-9]+(?:[._%+-][a-z0-9]+)*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;

// A name is made of letters only. Between words we allow a space, - or ' (like "Mary-Jane" or "O'Connor").
// \p{L} means "any letter", so names in other alphabets (accents, Urdu) also work. Digits are not allowed.
const NAME_REGEX = /^\p{L}+(?:[ '-]\p{L}+)*$/u;

// The only roles that exist
const ROLES = ["User", "Admin"];

// ---------- Helpers ----------

// Sanitize a text input (name, email):
// - anything that is not a string becomes "" (blocks objects like {"$ne": null})
// - control characters are removed, extra spaces are collapsed
// - < and > are removed, so HTML like <script> can't be stored
function sanitizeText(value) {
  if (typeof value !== "string") return "";
  return value
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .replace(/\s+/g, " ")
    .replace(/[<>]/g, "")
    .trim();
}

// Turn "admin", "ADMIN" or "Admin" into "Admin"
function normalizeRole(text) {
  return text.charAt(0).toUpperCase() + text.slice(1).toLowerCase();
}

// Check the register input. Returns a list of error messages (empty list = valid).
// "role" is optional: it is undefined when the client did not send it.
function validateRegister({ name, email, password, role }) {
  const errors = [];

  if (name.length < 2 || name.length > 100) {
    errors.push("name must be between 2 and 100 characters");
  } else if (!NAME_REGEX.test(name)) {
    errors.push("name must contain letters only (a space, - or ' is allowed between words)");
  }

  // The part before the @ may not be longer than 64 characters
  const localPart = email.split("@")[0];
  if (!EMAIL_REGEX.test(email) || email.length > 255 || localPart.length > 64) {
    errors.push("email must be a valid email address (for example ali123@abc.com)");
  }

  // The password is NOT sanitized, because changing it would change what the user typed.
  // bcrypt only reads the first 72 bytes, so we refuse anything longer.
  if (typeof password !== "string" || password.length < 8) {
    errors.push("password must be at least 8 characters");
  } else if (Buffer.byteLength(password) > 72) {
    errors.push("password must not be longer than 72 bytes");
  } else if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    errors.push("password must contain at least one letter and one number");
  }

  // Role: optional, but if it is sent it must be letters only, and either User or Admin
  if (role !== undefined) {
    if (!/^[A-Za-z]+$/.test(role)) {
      errors.push("role must contain letters only");
    } else if (!ROLES.includes(normalizeRole(role))) {
      errors.push("role must be either User or Admin");
    }
  }

  return errors;
}

function serverError(res, err) {
  console.error("Unexpected error:", err.message);
  return res.status(500).json({ error: "Internal server error" });
}

// ---------- POST /api/auth/register ----------

export async function register(req, res) {
  const body = req.body ?? {};

  const name = sanitizeText(body.name);
  const email = sanitizeText(body.email).toLowerCase();
  const password = body.password;
  const roleText = body.role === undefined ? undefined : sanitizeText(body.role);

  const errors = validateRegister({ name, email, password, role: roleText });
  if (errors.length) return res.status(400).json({ errors });

  // No role sent -> "User"
  const role = roleText === undefined ? "User" : normalizeRole(roleText);

  // Security rule: nobody can make themselves an Admin while registering,
  // otherwise anyone could simply send "role": "Admin".
  // Admins are created by changing the role in the database (UPDATE users SET role = 'Admin' ...).
  if (role === "Admin") {
    return res
      .status(403)
      .json({ error: "Admin accounts cannot be created through registration" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // $1, $2, $3, $4 are placeholders: values are sent separately from the SQL (no SQL injection)
    // RETURNING lists the columns we send back, and password is not one of them
    const result = await pool.query(
      `INSERT INTO users (name, email, password, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, role, created_at`,
      [name, email, hashedPassword, role]
    );

    return res.status(201).json({
      message: "User registered successfully",
      user: result.rows[0],
    });
  } catch (err) {
    // 23505 = unique violation, which means this email already exists
    if (err.code === "23505") {
      return res.status(409).json({ error: "Email is already registered" });
    }
    return serverError(res, err);
  }
}

// ---------- POST /api/auth/login ----------

export async function login(req, res) {
  const body = req.body ?? {};

  const email = sanitizeText(body.email).toLowerCase();
  const password = body.password;

  if (!email || typeof password !== "string" || password === "") {
    return res.status(400).json({ error: "email and password are required" });
  }

  try {
    const result = await pool.query(
      "SELECT id, name, email, password, role FROM users WHERE email = $1",
      [email]
    );
    const user = result.rows[0];

    // If the email does not exist we still compare against a fake hash.
    // This takes the same time as a real check, so nobody can find out
    // which emails are registered by measuring how fast the server answers.
    const passwordIsCorrect = await bcrypt.compare(
      password,
      user ? user.password : DUMMY_HASH
    );

    // Same message for "no such email" and "wrong password"
    if (!user || !passwordIsCorrect) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // The token holds only the id and role (never the password), and expires after JWT_EXPIRES_IN
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { algorithm: "HS256", expiresIn: process.env.JWT_EXPIRES_IN || "1h" }
    );

    return res.status(200).json({
      message: "Login successful",
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    return serverError(res, err);
  }
}

// ---------- GET /api/auth/profile (needs a valid token) ----------

export async function getProfile(req, res) {
  try {
    // req.user is set by the auth middleware after it verifies the token
    const result = await pool.query(
      "SELECT id, name, email, role, created_at FROM users WHERE id = $1",
      [req.user.id]
    );

    // The token was valid, but the user may have been deleted since
    if (!result.rows[0]) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json({ user: result.rows[0] });
  } catch (err) {
    return serverError(res, err);
  }
}

// ---------- GET /api/auth/users (Admin only) ----------
// Optional extra: gives the role middleware a real route to protect.
// You can delete this function (and its route) if you don't want it.

export async function getAllUsers(req, res) {
  try {
    const result = await pool.query(
      "SELECT id, name, email, role, created_at FROM users ORDER BY id"
    );
    return res.status(200).json({ count: result.rows.length, users: result.rows });
  } catch (err) {
    return serverError(res, err);
  }
}