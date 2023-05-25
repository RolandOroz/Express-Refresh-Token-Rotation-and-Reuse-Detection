const User = require("../model/User");

const handleLogout = async (req, res) => {
  // On client delete the accessToken
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(204); // No content
  const refreshToken = cookies.jwt;

  // Is refreshToken in DB
  const foundUser = await User.findOne({ refreshToken }).exec();
  if (!foundUser) {
    res.clearCookie("jwt", {
      httpOnly: true,
      sameSite: "None",
      //Comment when in DEV MODE
      //TODO PRODUCTION uncomment: secure: true
      //secure: true,
      // set to 1 Day (2 min only for DEV MODE)
      maxAge: 24 * 60 * 60 * 1000,
    });
    return res.sendStatus(204); // No content
  }

  // Delete refreshToken in DB
  foundUser.refreshToken = foundUser.refreshToken.filter(refTok => refTok !== refreshToken);
  const result = await foundUser.save();

  //TODO PRODUCTION = delete log
  console.log(result);

  res.clearCookie("jwt", {
    httpOnly: true,
    sameSite: "None",
    //Comment when in DEV MODE
    //TODO PRODUCTION uncomment: secure: true
    //secure: true,
    // set to 1 Day (2 min only for DEV MODE)
    maxAge: 24 * 60 * 60 * 1000,
  });
  res.sendStatus(204);
};

module.exports = { handleLogout }
