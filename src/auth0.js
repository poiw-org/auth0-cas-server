const request = require('request');
const stringify = require('node-stringify');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

exports.getCasServices = (config, cache, done) => {
  var services = cache.get('cas_services');
  if (services)
    return done(null, services);

  // get API V2 access_token
  request.post({
    url: `https://${config('AUTH0_DOMAIN')}/oauth/token`,
    json: {
      client_id: config('API_V2_CLIENT_ID'),
      client_secret: config('API_V2_CLIENT_SECRET'),
      audience: `https://${config('AUTH0_DOMAIN')}/api/v2/`,
      grant_type: 'client_credentials'
    }
  }, (err, response, body) => {
    if (err) return done(err);

    var accessToken = body.access_token;
    console.log('API v2 access token obtained.')

    // fetch clients from Auth0 that are configured as CAS services
    request.get({
      url: `https://${config('AUTH0_DOMAIN')}/api/v2/clients`,
      json: true,
      headers: { Authorization: `Bearer ${accessToken}` }
    }, (err, response, clients) => {
      if (err) return done(err);
      if (response.statusCode !== 200)
        return done(new Error(`Could not fetch Auth0 clients. status=${response.statusCode}, body=` + stringify(clients)));

      const webApps = clients
        .filter(c => c.app_type === 'regular_web' && c.client_metadata && c.client_metadata.cas_service);

      if (webApps.length === 0)
        return done(new Error(`No clients representing CAS Services could be found in Auth0 tenant ${config('AUTH0_DOMAIN')}.`));

      services = {};
      cache.set('cas_services', services);
      for (var i = 0; i < webApps.length; i++) {
        const webApp = webApps[i];

        services[webApp.client_metadata.cas_service] = {
          client_id: webApp.client_id,
          client_secret: webApp.client_secret
        }
      }

      console.log(`CAS services discovered in Auth0 tenant ${config('AUTH0_DOMAIN')}:\n`,
        services);

      done(null, services);
    });
  });
};

exports.getIdTokenSecret = (config, service, idToken, cache, done) => {
  // make sure cache for secrets is initialized
  var idTokenSecrets = cache.get('id_token_secrets');
  if (!idTokenSecrets) {
    idTokenSecrets = {};
    cache.set('id_token_secrets', idTokenSecrets);
  }

  // check to see if secret is already in cache
  if (idTokenSecrets[service.client_id])
    return done(null, idTokenSecrets[service.client_id]);

  const decoded = jwt.decode(idToken, { complete: true });
  if (!decoded)
    return done(new Error('Invalid JWT!'));

  switch (decoded.header.alg) {
    case 'HS256':
      console.log(`Caching id_token HS256 validation secret for client_id: ${service.client_id}`);

      idTokenSecrets[service.client_id] = new Buffer(service.client_secret, 'base64');
      return done(null, idTokenSecrets[service.client_id]);
    case 'RS256':
      console.log(`Caching id_token RS256 validation public key for client_id: ${service.client_id}`);

      const client = jwksClient({ jwksUri: `https://${config('AUTH0_DOMAIN')}/.well-known/jwks.json` });
      return client.getSigningKey(decoded.header.kid, (err, key) => {
        if (err) return done(err);
        
        idTokenSecrets[service.client_id] = key.publicKey || key.rsaPublicKey;
        return done(null, idTokenSecrets[service.client_id]);
      });
    default:
      return done(new Error(`Unsupported id_token signing algorithm: ${decoded.header.alg}`));
  }
};
