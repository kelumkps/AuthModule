var log = require('./libs/log')(module);
var UserModel = require('./libs/model/auth/user');
var ClientModel = require('./libs/model/auth/client');
var AccessTokenModel = require('./libs/model/auth/accessToken');
var RefreshTokenModel = require('./libs/model/auth/refreshToken');
var faker = require('Faker');
require('./libs/db/mongoose');

UserModel.remove({}, function(err) {
    var user = new UserModel({
        username: "andrey",
        password: "simplepassword"
    });
    user.save(function(err, user) {
        if (err) return log.error(err);
        else log.info("New user - %s:%s", user.username, user.password);
    });

    for (i = 0; i < 4; i++) {
        var user = new UserModel({
            username: faker.random.first_name().toLowerCase(),
            password: faker.Lorem.words(1)[0]
        });
        user.save(function(err, user) {
            if (err) return log.error(err);
            else log.info("New user - %s:%s", user.username, user.password);
        });
    }
});

ClientModel.remove({}, function(err) {
    var client = new ClientModel({
        name: "OurService iOS client v1",
        clientId: "mobileV1",
        clientSecret: "abc123456",
        domains: "localhost"
    });
    client.save(function(err, client) {
        if (err) return log.error(err);
        else log.info("New client - %s:%s", client.clientId, client.clientSecret);
    });
});
AccessTokenModel.remove({}, function(err) {
    if (err) return log.error(err);
});
RefreshTokenModel.remove({}, function(err) {
    if (err) return log.error(err);
});

setTimeout(function() {
    process.exit();
}, 5000);