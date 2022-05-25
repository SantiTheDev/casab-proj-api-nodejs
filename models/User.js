const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: true,
        min: 6,
        max: 255
    },
    phone: {
        type: Number,
        required: true,
        minlength: 6
    },
    email: {
        type: String,
        required: true,
        min: 6,
        max: 1024
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    username:{
        type: String,
        require: true,
        min: 6,
        max: 50
    },
    last_accesed_ip: {
        type: String,
        required: true,
        min: 6,
        max: 30
    },
    date: {
        type: Date,
        default: Date.now
    },
    role: {
        type: String,
        default: "guest"
    }
})

module.exports = mongoose.model('User', userSchema);