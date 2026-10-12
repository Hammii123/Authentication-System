import express from "express";
import helmet from "helmet";
import authRoutes from "./routes/auth.routes.js";

const app = express();

// Security headers
app.use(helmet());

// Parse JSON request bodies
app.use(express.json({ limit: "10kb" }));

// Mount authentication routes
app.use("/api/auth", authRoutes);

export default app;