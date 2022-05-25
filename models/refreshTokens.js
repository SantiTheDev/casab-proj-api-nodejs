const mongoose = require('mongoose');

const refreshTokensSchema = mongoose.Schema({
    token: {
        type: String,
        required: true,
        min: 6,
        max: 255
    }
})

module.exports = mongoose.model('refreshTokens', refreshTokensSchema);