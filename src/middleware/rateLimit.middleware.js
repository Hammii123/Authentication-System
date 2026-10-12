import rateLimit from "express-rate-limit";

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100,                // Maximum 100 requests per window
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Too many authentication attempts. Try again later.",
  },
});

export default authLimiter;