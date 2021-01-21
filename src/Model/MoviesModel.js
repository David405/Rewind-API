var mongoose = require('mongoose');

const movieSchema = new mongoose.Schema({
    name: {
        type: [],
        required: true,
        unique: true
    },
    description: {
        type: String,
        required: false
    },
    path: {
        type: String,
        required: true
    },
    id: {
        type: String,
        required: true
    }
})

module.exports = mongoose.model('Movie', movieSchema);
