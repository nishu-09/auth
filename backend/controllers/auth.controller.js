const User = require('../models/user')
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { generateAccessToken, generateRefreshToken } = require("../utils/generate_token")

const UserController = {

    // ================= REGISTER =================

    register: async (req, res) => {
        try {
            const { name, email, password } = req.body

            const existEmail = await User.findOne({ email: email })
            if (existEmail) {
                return res.status(200).json({
                    success: false,
                    message: "Email already exists"
                })
            }

            const hashedPassword = await bcrypt.hash(password, 10)

            const newUser = User({
                name,
                email,
                password: hashedPassword
            })

            const refreshToken = generateRefreshToken(newUser);
            newUser.refresh_token = refreshToken;
            await newUser.save();
            // Set Cookies
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

            return res.status(201).json({
                message: "User registered successfully",
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Internal server error"
            })
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

            const isMatchPassword = bcrypt.compare(password, existUser.password)
            if (!isMatchPassword) {
                return res.status(200).json({
                    status: false,
                    message: "Invalid Password or Email"
                })
            }

            const refreshToken = generateRefreshToken(existUser);
            const accessToken = generateAccessToken(existUser)
            existUser.refresh_token = refreshToken;

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

            const user = await User.findOne({ refreshToken });
            if (!user)
                return res.status(403).json({ message: "Invalid refresh token" });

            jwt.verify(
                refreshToken,
                process.env.REFRESH_TOKEN_SECRET,
                async (err, decoded) => {
                    if (err)
                        return res.status(403).json({ message: "Invalid refresh token" });

                    // Rotate tokens
                    const tokens = generateTokens(user._id);

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
                { refreshToken },
                { $set: { refreshToken: null } }
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