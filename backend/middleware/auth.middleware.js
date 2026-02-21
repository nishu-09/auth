const jwt = require('jsonwebtoken')

const AuthMiddleware = async (req, res, next) => {
    try {
        const token = req.cookies.accessToken;
        if (!token) {
            return res.status(401).json({
                message: "Not authorized, no token"
            });
        }
        const decoded = jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET
        );
        req.user = decoded; // contains { id }
        next();
    } catch (err) {
        return res.status(401).json({
            message: "Token invalid or expired"
        });
    }
}

module.exports = AuthMiddleware