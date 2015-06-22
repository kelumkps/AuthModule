# Authentication Module for Node REST APIs

Authentication Module for REST APIs using Node.js and Express.js framework with Mongoose.js for working with MongoDB. For access control this project use OAuth 2.0, with the help of OAuth2orize and Passport.js.

This code is based on [RESTful API With Node.js + MongoDB](http://aleksandrov.ws/2013/09/12/restful-api-with-nodejs-plus-mongodb) and [Hosting an OAuth2.0 Service in Passport.js with Mongoose](http://z43studio.com/2014/07/oauth2/) articles.

## Running project

You need to have installed Node.js and MongoDB 

### Install dependencies 

To install dependencies enter project folder and run following command:
```
npm install
```

### Run server

To run server execute:
```
node server.js
```

### Obtain Access Tokens by exchanging username & password

```
curl -H "Accept: application/json" -H "Content-type: application/json"  --data @data\auth-token-req.json -X POST http://localhost:1337/oauth/token
```

### Exchange refreshToken for an access token

```
curl -H "Accept: application/json" -H "Content-type: application/json" --data @data\refresh-token-req.json -X POST http://localhost:1337/oauth/token
```

### Obtain Grant code 

```
http://localhost:1337/auth/start?client_id=mobileV1&response_type=code&scope=edit_account,do_things&redirect_uri=http://localhost/test
```

### Exchange Grant Codes for Access Tokens

```
curl -H "Accept: application/json" -H "Content-type: application/json" -X POST --data @data\auth-token-by-code-req.json http://localhost:1337/auth/exchange
```

### Call API end points with Access Token

```
curl -H "Authorization: Bearer TOKEN" -X GET http://localhost:1337/api/articles
```

## Modules used

Some of non standard modules used:
* [express](https://www.npmjs.com/package/mongoose)
* [mongoose](https://www.npmjs.com/package/mongoose)
* [nconf](https://www.npmjs.com/package/nconf)
* [winston](https://www.npmjs.com/package/winston)
* [oauth2orize](https://www.npmjs.com/package/oauth2orize)
* [passport](https://www.npmjs.com/package/passport)

