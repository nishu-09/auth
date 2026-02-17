const express = require('express')
const AuthController = require('../controllers/auth.controller')
const router = express.Router()
const AuthMiddleware = require('../middleware/auth.middleware')

// Register
router.post('/register',AuthController.register)

// Verify OTP
router.post("/verify-otp", AuthController.verifyOtp);

// Resend OTP
router.post("/resend-otp", AuthController.resendOtp);

// Login
router.post('/login',AuthController.login)

// Forgot password
router.post("/forgot-password", AuthController.forgotPassword);

// Verify Forgot pass OTP
router.post("/verify-forgot-otp", AuthController.verifyForgotOtp);

// Reset Password
router.post("/reset-password", AuthController.resetPassword);

// Rotate Token
router.post("/refresh", AuthController.refreshToken);

//Logout
router.post("/logout", AuthController.logout);

// Profile
router.get("/profile",AuthMiddleware,AuthController.profile);

//Google login
router.post("/google-login", AuthController.googleLogin);

module.exports = router