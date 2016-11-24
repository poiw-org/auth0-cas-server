const uuid = require('node-uuid');
const querystring = require('querystring');
const jwt = require('jsonwebtoken');
const url = require('url');
const request = require('request');
const stringify = require('node-stringify');
const xmlbuilder = require('xmlbuilder');
const moment = require('moment');

const auth0 = require('./auth0');

function buildUrl (req, path) {
  const originalUrl = url.parse(req.originalUrl || '').pathname || '';
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';

  return url.format({
    protocol: isSecure ? 'https' : 'http',
    host: req.get('host'),
    pathname: originalUrl.replace(req.path, path)
  });
}

// CAS login endpoint
exports.login = (config) =>
  (req, res) => {
    // generate session
    req.session.state = uuid.v4();
    req.session.serviceUrl = req.query.service;

    // perform OIDC Authorizaation Code Flow with Auth0
    const query = querystring.stringify({
      client_id: req.service.client_id,
      response_type: 'code',
      scope: config('AUTH0_SCOPES'),
      redirect_uri: buildUrl(req, '/callback'),
      connection: config('AUTH0_CONNECTION'),
      state: req.session.state
    });
    res.redirect(`https://${config('AUTH0_DOMAIN')}/authorize?${query}`);
  };

// CAS validate endpoint
exports.validate = (config, cache) =>
  (req, res) => {
    // response helper functions
    function sendServiceResponse (status, body) {
      res.status(status);

      const response = {
        serviceResponse: body
      };

      // send XML unless JSON was requested
      res.format({
        xml: () => {
          const xml = xmlbuilder.create(response, {
            stringify: {
              eleName: (name) => 'cas:' + name
            }
          });
          xml.att('xmlns:cas', 'http://www.yale.edu/tp/cas');

          res.send(xml.end({ pretty: true }));
        },
        json: () => {
          res.json(response);
        }
      });
    }

    function sendFailure (status, code, description) {
      sendServiceResponse(status, {
        authenticationFailure: {
          '@code': code,
          '#text': description
        }
      });
    }

    function sendError (err) {
      const description = `Error ID ${uuid.v4()}`;
      // log error
      console.log(`${description}:`, err);

      sendFailure(500, 'SERVER_ERROR', description);
    }

    // perform OAuth2 code/token exchange with Auth0, using ticket as code
    request.post({
      url: `https://${config('AUTH0_DOMAIN')}/oauth/token`,
      json: {
        code: req.query.ticket,
        client_id: req.service.client_id,
        client_secret: req.service.client_secret,
        grant_type: 'authorization_code',
        redirect_uri: buildUrl(req, '/callback')
      }
    }, (err, response, body) => {
      if (err)
        return sendError(err);
      if (response.statusCode != 200)
        return sendFailure(400, 'INVALID_TICKET', stringify(body));

      // get secret used to validate the id_token
      auth0.getIdTokenSecret(config, req.service, body.id_token, cache, (err, idTokenSecret) => {
        if (err)
          return sendError(err);

        // validate the id_token and return its payload in CAS format
        jwt.verify(
          body.id_token,
          idTokenSecret,
          {
            audience: req.service.client_id,
            issuer: `https://${config('AUTH0_DOMAIN')}/`
          },
          (err, payload) => {
            if (err)
              return sendError(err);

            // generate authenticationDate
            payload.authenticationDate = moment.unix(payload.iat).utc().format();

            // remove claims we don't want in the response
            ['identities', 'iss', 'sub', 'aud', 'exp', 'iat']
              .forEach(claim => {
                delete payload[claim];
              });

            // send success response
            sendServiceResponse(200, {
              authenticationSuccess: {
                user: payload[config('CAS_USERNAME_FIELD')],
                attributes: payload
              }
            });
          });
      });
    });
  };
