const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        unique: true,
        trim: true,
        required: true
    },
    googleId: {
        type: String,
        default: null
    },
    provider: {
        type: String,
        enum: ['local', 'google'],
        default: 'local'
    },
    password: {
        type: String,
        required: function () {
            return this.provider === 'local';
        }
    },
    is_verified: {
        type: Boolean,
        default: false
    },
    refresh_token: {
        type: String,
        default:null
    }

}, { timestamps: true })

module.exports = mongoose.model('User', userSchema)
