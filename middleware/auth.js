const jwt = require("jsonwebtoken")

const auth = (req, res, next) => {
    console.log(req.cookies)
    const {token} = req.cookies

    // what if token is not there
    if (!token) {
        return res.status(403).send("token is missing")
    }

    // verify token
    try {
        const decode = jwt.verify(token, process.env.SECRET)
        req.user = decode

        // extract id from token and query the DB


    } catch (error) {
        res.status(403).send("token is invalid")
    }

    return next()
}

module.exports = auth


