var mongoose = require('mongoose');

var Schema = mongoose.Schema;

var GrantCode = new Schema({
    code: {
        type: String, unique: true
    },
    user: {type: String, required: true},
    client: {type: String, required: true},
    scope: [{type: String}],
    active: {type: Boolean, default: true},
    created: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('GrantCode', GrantCode);