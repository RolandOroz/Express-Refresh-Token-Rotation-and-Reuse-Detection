const User = require("../model/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");


const handleLogin = async (req, res) => {
  const cookies = req.cookies;
  const { user, pwd } = req.body;
  if (!user || !pwd)
    return res
      .status(400)
      .json({ message: "Username and password are required." });
      
  const foundUser = await User.findOne({ username: user }).exec();
  if (!foundUser) return res.sendStatus(401); //unauthorized
  
  // evaluate password
  const match = await bcrypt.compare(pwd, foundUser.password);
  if (match) {
    const roles = Object.values(foundUser.roles).filter(Boolean);
    // create JWTs
    const accessToken = jwt.sign(
      {
        "UserInfo": {
          "username": foundUser.username,
          "roles": roles,
        }
      },
      process.env.ACCESS_TOKEN_SECRET,
      // set to 'n' min (45s only for DEV MODE)
      { expiresIn: "300s" }
    );


    const refreshToken = jwt.sign(
      { "username": foundUser.username },
      process.env.REFRESH_TOKEN_SECRET,
      // set to 'n' Day (2 min only for DEV MODE)
      { expiresIn: "1d" }
    );

    const newRefreshTokenArray = !cookies?.jwt
      ? foundUser.refreshToken
      : foundUser.refreshToken.filter((refTok) => refTok !== cookies.jwt);

    if (cookies?.jwt)
      res.clearCookie("jwt", {
        httpOnly: true,
        sameSite: "None",
        //Comment when in DEV MODE
        //TODO PRODUCTION uncomment: secure: true
        //secure: true,
        // set to 1 Day (2 min only for DEV MODE)
        maxAge: 24 * 60 * 60 * 1000,
      });

    // MongoDB
    // Saving refreshToken with current user
    foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
    const result = await foundUser.save();

    //TODO PRODUCTION delete logs
    console.log(result);
    console.log(roles);

    // Creates Secure Cookie with refresh token
    res.cookie("jwt", newRefreshToken, {
      httpOnly: true,
      sameSite: "None",
      //TODO PRODUCTION uncomment secure: true when not in DEV MODE
      //TODO PRODUCTION uncomment secure: true,
      //secure: true,
      // set to 'n' Day (2 min only for DEV MODE)
      maxAge: 24 * 60 * 60 * 1000,
    });
    res.json({ roles, accessToken });
  } else {
    res.sendStatus(401); //Unauthorized
  }
};

module.exports = { handleLogin }
