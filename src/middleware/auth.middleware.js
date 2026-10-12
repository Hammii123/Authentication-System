import jwt from "jsonwebtoken";

export function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  // Expect: Authorization: Bearer <token>
  const token = authHeader?.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : null;

  if (!token) {
    return res.status(401).json({
      error: "Access denied. Token required.",
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"],
    });

    req.user = decoded;

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token.",
    });
  }
}