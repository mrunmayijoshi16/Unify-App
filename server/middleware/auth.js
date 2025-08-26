import jwt from "jsonwebtoken";

export function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  jwt.verify(token, process.env.JWT_SECRET || "mysecretkey", (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = user; // attach decoded user info to request
    next();
  });
}
