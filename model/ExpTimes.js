const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ExpTimes = new Schema({
    expire_time: {
        short: {
            type: String,
            required: true
        },
        medium: {
            type: String,
            required: true
        },
        long: {
            type: String,
            required: true
        }
    }
});