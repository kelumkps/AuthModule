var winston = require('winston');
var config = require('./config');
var pathModule = require('path'); // path parsing module

function getLogger(module) {
    var path = module.filename.split(pathModule.sep).slice(-2).join(pathModule.sep); //using filename in log statements

    return new winston.Logger({
        transports: [
            new winston.transports.Console({
                colorize: true,
                level: config.get('logger:level:console'),
                label: path
            })
        ]
    });
}

module.exports = getLogger;