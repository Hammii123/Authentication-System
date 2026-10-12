import express from "express";
import { authorizeRoles } from "../middleware/role.middleware.js";

import {
  register,
  login,
  getProfile,
  getAllUsers,
} from "../controllers/auth.controller.js";

import authLimiter from "../middleware/rateLimit.middleware.js";

import { authenticateToken } from "../middleware/auth.middleware.js";

const router = express.Router();

// Public routes — no login required
router.post("/register", authLimiter ,register);
router.post("/login",authLimiter ,login);

// Protected route — valid JWT required
router.get("/profile", authenticateToken, getProfile);

// Admin route — we'll add role checking next
router.get(
  "/users",
  authenticateToken,
  authorizeRoles("Admin"),
  getAllUsers
);

export default router;