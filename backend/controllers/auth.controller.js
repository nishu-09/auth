const User = require('../models/user')
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Otp = require("../models/otp");
const sendEmail = require("../utils/send_email");
const { generateAccessToken, generateRefreshToken } = require("../utils/generate_token")
const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const UserController = {

    // ================= REGISTER =================

    register: async (req, res) => {
        try {
            const { name, email, password } = req.body;

            const existEmail = await User.findOne({ email });
            if (existEmail) {
                return res.status(400).json({
                    success: false,
                    message: "Email already exists"
                });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            const newUser = new User({
                name,
                email,
                password: hashedPassword,
                is_verified: false
            });

            await newUser.save();

            // Generate 6-digit OTP
            const otp = Math.floor(100000 + Math.random() * 900000).toString();
            const hashedOtp = await bcrypt.hash(otp, 10)
            await Otp.create({
                userId: newUser._id,
                otp: hashedOtp,
                expires_at: Date.now() + 5 * 60 * 1000 // 5 minutes
            });

            // Send RAW OTP to email
            await sendEmail({
                to: email,
                subject: "Verify Your Email",
                template: "otp",
                data: {
                    otp,
                    name,
                    appName: "MyAuthApp",
                    title: "Verify Your Email",
                    heading: "Email Verification",
                    message: "Please use the OTP below to verify your email address."
                }
            });


            return res.status(201).json({
                success: true,
                message: "OTP sent to email. Please verify."
            });

        } catch (error) {
            console.log("REGISTER ERROR:", error);
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }

    },

    // ================= VERIFY =================

    verifyOtp: async (req, res) => {
        try {
            const { email, otp } = req.body;

            const user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({
                    success: false,
                    message: "User not found"
                });
            }

            const otpRecord = await Otp.findOne({ userId: user._id });
            if (!otpRecord) {
                return res.status(400).json({
                    success: false,
                    message: "OTP not found"
                });
            }

            //  Check Expiry
            if (otpRecord.expires_at < new Date()) {
                return res.status(400).json({
                    success: false,
                    message: "OTP expired"
                });
            }

            //  Compare hashed OTP
            const isMatch = await bcrypt.compare(otp, otpRecord.otp);

            if (!isMatch) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid OTP"
                });
            }

            // Mark verified
            user.is_verified = true;
            await user.save();

            //  Delete OTP after success
            await Otp.deleteMany({ userId: user._id });

            return res.json({
                success: true,
                message: "Email verified successfully"
            });

        } catch (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }
    },


    // ================= RESEND OTP ================= 

    resendOtp: async (req, res) => {
        try {
            const { email } = req.body
            const user = await User.findOne({ email });

            if (!user) {
                return res.status(400).json({
                    success: false,
                    message: "User not found"
                });
            }

            if (user.is_verified) {
                return res.status(400).json({
                    success: false,
                    message: "User already verified"
                });
            }

            // Delete old OTP
            await Otp.deleteMany({ userId: user._id });

            const otp = Math.floor(100000 + Math.random() * 900000).toString();
            const hashedOtp = await bcrypt.hash(otp, 10)

            await Otp.create({
                userId: user._id,
                otp: hashedOtp,
                expires_at: new Date(Date.now() + 5 * 60 * 1000)
            });

            await sendEmail({
                to: email,
                subject: "Verify Your Email",
                template: "otp",
                data: {
                    otp,
                    name: user.name,
                    appName: "MyAuthApp",
                    title: "Verify Your Email",
                    heading: "Email Verification",
                    message: "Please use the OTP below to verify your email address."
                }
            });


            return res.json({
                success: true,
                message: "OTP resent successfully"
            });
        } catch (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }
    },

    // ================= LOGIN ================= 

    login: async (req, res) => {
        try {
            const { email, password } = req.body

            const existUser = await User.findOne({ email: email })
            if (!existUser) {
                return res.status(200).json({
                    success: false,
                    message: "User not found"
                })
            }

            const isMatchPassword = await bcrypt.compare(password, existUser.password);
            if (!isMatchPassword) {
                return res.status(200).json({
                    status: false,
                    message: "Invalid Password or Email"
                })
            }

            const refreshToken = generateRefreshToken(existUser);
            const accessToken = generateAccessToken(existUser)
            existUser.refresh_token = refreshToken;
            await existUser.save();


            res.cookie("accessToken", accessToken, {
                httpOnly: true,
                secure: false,
                sameSite: "Lax",
                maxAge: 15 * 60 * 1000,
            });

            res.cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: false,
                sameSite: "Lax",
                maxAge: 7 * 24 * 60 * 60 * 1000,
            });

            return res.json({ message: "Login successful" });

        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Internal server error"
            })
        }
    }
    ,

    // ================= FORGET PASSWORD =================
    forgotPassword: async (req, res) => {
        try {
            const { email } = req.body
            const user = await User.findOne({ email });

            if (!user) {
                return res.status(400).json({
                    success: false,
                    message: "User not found"
                });
            }

            // Delete old OTPs
            await Otp.deleteMany({ userId: user._id });

            // Generate OTP
            const otp = Math.floor(100000 + Math.random() * 900000).toString();

            const hashedOtp = await bcrypt.hash(otp, 10);

            await Otp.create({
                userId: user._id,
                otp: hashedOtp,
                expires_at: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
            });

            await sendEmail({
                to: email,
                subject: "Reset Your Password",
                template: "otp",
                data: {
                    otp,
                    name: user.name,
                    appName: "MyAuthApp",
                    title: "Password Reset",
                    heading: "Reset Your Password",
                    message: "Use the OTP below to reset your account password."
                }
            });

            return res.json({
                success: true,
                message: "Password reset OTP sent to your email"
            });


        } catch (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }
    },

    // ================= Verify OTP for Password Reset =================
    verifyForgotOtp: async (req, res) => {
        try {
            const { email, otp } = req.body;

            const user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({
                    success: false,
                    message: "User not found"
                });
            }

            const otpRecord = await Otp.findOne({ userId: user._id });
            if (!otpRecord) {
                return res.status(400).json({
                    success: false,
                    message: "OTP not found"
                });
            }

            if (otpRecord.expires_at < new Date()) {
                return res.status(400).json({
                    success: false,
                    message: "OTP expired"
                });
            }

            const isMatch = await bcrypt.compare(otp, otpRecord.otp);

            if (!isMatch) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid OTP"
                });
            }

            return res.json({
                success: true,
                message: "OTP verified successfully"
            });

        } catch (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }

    },

    resetPassword: async (req, res) => {
        try {
            const { email, newPassword } = req.body
            const user = await User.findOne({ email })
            if (!user) {
                return res.status(200).json({
                    success: false,
                    message: "User not found"
                })
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);

            user.password = hashedPassword;
            await user.save();

            // Delete OTP after successful reset
            await Otp.deleteMany({ userId: user._id });
            return res.json({
                success: true,
                message: "Password reset successfully"
            });

        } catch (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            })
        }
    },

    // ================= REFRESH TOKEN (Rotation) =================
    refreshToken: async (req, res) => {
        try {
            const refreshToken = req.cookies.refreshToken;

            if (!refreshToken)
                return res.status(401).json({ message: "No refresh token provided" });

            const user = await User.findOne({ refresh_token: refreshToken })
            if (!user)
                return res.status(403).json({ message: "Invalid refresh token" });

            jwt.verify(
                refreshToken,
                process.env.REFRESH_TOKEN_SECRET,
                async (err, decoded) => {
                    if (err)
                        return res.status(403).json({ message: "Invalid refresh token" });

                    // Rotate tokens
                    const tokens = generateRefreshToken(user);

                    user.refresh_token = tokens.refreshToken;
                    await user.save();

                    res.cookie("accessToken", tokens.accessToken, {
                        httpOnly: true,
                        secure: false,
                        sameSite: "Lax",
                        maxAge: 15 * 60 * 1000,
                    });

                    res.cookie("refreshToken", tokens.refreshToken, {
                        httpOnly: true,
                        secure: false,
                        sameSite: "Lax",
                        maxAge: 7 * 24 * 60 * 60 * 1000,
                    });

                    return res.json({ success: true, message: "Token refreshed" });
                }
            );

        } catch (error) {
            return res.status(500).json({ success: false, message: error.message });
        }
    },

    // ================= PROFILE =================
    profile: async (req, res) => {
        try {
            const user = await User.findById(req.user.id)
                .select("-password -refresh_token");
            return res.status(200).json({ success: true, profile_data: user });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Internal server error"
            })
        }
    },

    // ================= LOGOUT =================
    logout: async (req, res) => {
        try {
            const refreshToken = req.cookies.refreshToken;

            await User.updateOne(
                { refresh_token: refreshToken },
                { $set: { refresh_token: null } }
            );


            res.clearCookie("accessToken");
            res.clearCookie("refreshToken");

            return res.json({ success: true, message: "Logged out successfully" });

        } catch (error) {
            return res.status(500).json({ success: false, message: error.message });
        }
    },

    // ================= GOOGLE Login =================
    googleLogin: async (req, res) => {
        try {
            const { credential } = req.body;

            if (!credential) {
                return res.status(400).json({
                    success: false,
                    message: "Google token missing"
                });
            }

            //  Verify Google ID token
            const ticket = await client.verifyIdToken({
                idToken: credential,
                audience: process.env.GOOGLE_CLIENT_ID,
            });

            const payload = ticket.getPayload();
            const { sub, email, name, picture } = payload;

            let user = await User.findOne({ email });

            //  If user does not exist → create
            if (!user) {
                user = new User({
                    name,
                    email,
                    googleId: sub,
                    provider: "google",
                    avatar: picture,
                    is_verified: true   // Google already verifies email
                });

                await user.save();
            }

            //  If user exists but registered locally → link Google
            if (user && !user.googleId) {
                user.googleId = sub;
                user.provider = "google";
                user.is_verified = true;
                await user.save();
            }

            //  Generate tokens (same as your login)
            const refreshToken = generateRefreshToken(user);
            const accessToken = generateAccessToken(user);

            user.refresh_token = refreshToken;
            await user.save();

            //  Set cookies (same as your login)
            res.cookie("accessToken", accessToken, {
                httpOnly: true,
                secure: false,
                sameSite: "Lax",
                maxAge: 15 * 60 * 1000,
            });

            res.cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: false,
                sameSite: "Lax",
                maxAge: 7 * 24 * 60 * 60 * 1000,
            });

            return res.json({
                success: true,
                message: "Google login successful"
            });

        } catch (error) {
            console.log("GOOGLE LOGIN ERROR:", error);
            return res.status(401).json({
                success: false,
                message: "Invalid Google token"
            });
        }
    }


}

module.exports = UserController