const tokenService = require('../services/token-service');

module.exports = async function (req, res, next) {
    try {
        if(!req.cookies) {
            res.status(404).json({ message: 'No cookies recieved'})
        }
        const { accessToken } = req.cookies;
        console.log(req.cookies);
        if (!accessToken) {
            throw new Error();
        }
        const userData = await tokenService.verifyAccessToken(accessToken);
        if (!userData) {
            throw new Error();
        }
        req.user = userData;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token', error: err });
    }
};
