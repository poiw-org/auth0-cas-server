const uuid = require('node-uuid');
const querystring = require('querystring');
const jwt = require('jsonwebtoken');
const url = require('url');
const request = require('request');
const stringify = require('node-stringify');

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
      scope: 'openid profile',
      redirect_uri: buildUrl(req, '/callback'),
      connection: config('AUTH0_CONNECTION'),
      state: req.session.state
    });
    res.redirect(`https://${config('AUTH0_DOMAIN')}/authorize?${query}`);
  };

// CAS validate endpoint
exports.validate = (config) =>
  (req, res) => {
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
      if (err) throw err;
      if (response.statusCode != 200) return res.status(400).send(`IDP returned a non-successful response: ${stringify(body)}`);

      //TODO: support both HS256 and RS256 verification

      // validate the id_token and return its payload in CAS format
      jwt.verify(body.id_token, new Buffer(req.service.client_secret, 'base64'), (err, payload) => {
        if (err) throw err;

        //TODO: format payload as CAS XML
        res.send(payload);
      });
    });
  };
