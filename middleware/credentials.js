const whiteList = require("./../config/whiteList");

const credentials = (req, res, next) => {
    const origin = req.headers.origin;
    if (whiteList.includes(origin)) {
        res.header("Acces-Control-Allow-Credentials", true);
    }
    next();
}

module.exports = credentials