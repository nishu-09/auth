const express = require('express')
const AuthController = require('../controllers/auth.controller')
const router = express.Router()
const AuthMiddleware = require('../middleware/auth.middleware')

router.post('/register',AuthController.register)
// Verify OTP
router.post("/verify-otp", AuthController.verifyOtp);
// Resend OTP
router.post("/resend-otp", AuthController.resendOtp);
router.post('/login',AuthController.login)
router.post("/refresh", AuthController.refreshToken);
router.post("/logout", AuthController.logout);
router.get("/profile",AuthMiddleware,AuthController.profile);

module.exports = router