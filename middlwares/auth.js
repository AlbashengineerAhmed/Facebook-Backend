const jwt = require("jsonwebtoken");

exports.authUser = async (req, res, next) => {
  try {
    const authHeader = req.header("Authorization");

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "No token provided or bad format" });
    }

    const token = authHeader.split(" ")[1]; // safely get the token
    const secret = process.env.TOKEN_SECRET || "ahmed72261";

    const decoded = jwt.verify(token, secret);

    req.user = decoded;
    next();
  } catch (error) {
    console.error("JWT Auth Error:", error.message);
    return res.status(401).json({ message: "Invalid Authentication" });
  }
};

