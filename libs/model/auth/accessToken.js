var mongoose = require('mongoose');

var Schema = mongoose.Schema;

var AccessToken = new Schema({
    userId: {
        type: String,
        required: true
    },
    clientId: {
        type: String,
        required: true
    },
    token: {
        type: String,
        unique: true,
        required: true
    },
    created: {
        type: Date,
        default: Date.now
    },
    grant: {type: Schema.Types.ObjectId, ref: 'GrantCode'},
    scope: [{type: String}]
});

module.exports = mongoose.model('AccessToken', AccessToken);