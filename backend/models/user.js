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
    // mobile: {
    //     type: String,
    //     required: true,
    // },
    is_verified: {
        type: Boolean,
        default: false
    },
    password: {
        type: String,
        require: true
    },
    refresh_token: {
        type: String,
    }
}, { timeStamps: true })

module.exports = mongoose.model('User', userSchema)