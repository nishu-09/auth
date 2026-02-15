const User = require('../models/user')
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Otp = require("../models/otp");
const sendEmail = require("../utils/send_email");
const { generateAccessToken, generateRefreshToken } = require("../utils/generate_token")

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
                    appName: "MyAuthApp"
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

            // 🧹 Delete OTP after success
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
                to: user.email,
                subject: "Verify Your Email",
                template: "otp",
                data: {
                    otp,
                    appName: "MyAuthApp"
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

                    return res.json({ message: "Token refreshed" });
                }
            );

        } catch (error) {
            return res.status(500).json({ message: error.message });
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

            return res.json({ message: "Logged out successfully" });

        } catch (error) {
            return res.status(500).json({ message: error.message });
        }
    }


}

module.exports = UserController