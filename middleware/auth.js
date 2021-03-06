const jwt = require("jsonwebtoken");
const config = require("config");


//middleware function
module.exports = function (req, res, next) {
    
  //get token from the header
const token = req.header("x-auth-token");

  //check if not token
  if (!token) {
    return res.status(401).json({ msg: "No token, authorization denied" });
  }

  // if there is a token - verification
  try {
    const decoded = jwt.verify(token, config.get("jwtSecret"));

    req.user = decoded.user;

      next();
      
  } catch (err) {
    res.status(401).json({ msg: "Token is not valid" });
  }
};