import "dotenv/config";
import app from "./app.js";

const PORT = process.env.PORT || 3000;

if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET is missing from .env");
}

app.listen(PORT, () => {
  console.log(`Server is running on port http://localhost${PORT}`);
});