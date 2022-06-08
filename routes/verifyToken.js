const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {

    // get the request header
    const token = req.header('auth-token');
    // check if token is empty or null
    if(!token) return res.status(401).send('Access denied.');


    // catch any errors if token is not verified
    try {

        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();

    } catch(err) {

        res.status(400).send({
            "status": "invalid token", 
            "error msg": err
        });

    }
}