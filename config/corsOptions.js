const whiteList = require("./whiteList")
const corsOptions = {
  origin: (origin, callback) => {
    //set to no origin(!origin) only in DEV MODE!!
    if (whiteList.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  optionsSuccessStatus: 200,
};

module.exports = corsOptions;