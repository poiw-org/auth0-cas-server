const request = require('supertest');
const nock = require('nock');
const expect = require('chai').expect;
const url = require('url');
const xmldom = require('xmldom');
const xpath = require('xpath');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const server = require('../src/server');

function mockFetchApiToken () {
  return nock('https://fake-tenant.auth0.com')
    .post('/oauth/token', {
      client_id: 'client_id',
      client_secret: 'client_secret',
      audience: 'https://fake-tenant.auth0.com/api/v2/',
      grant_type: 'client_credentials'
    })
    .reply(200, {
      access_token: 'access_token'
    });
}

function mockFetchClients() {
  return nock('https://fake-tenant.auth0.com', {
      reqheaders: { authorization: 'Bearer access_token' }
    })
    .get('/api/v2/clients')
    .reply(200, [
      {
        app_type: 'regular_web',
        client_metadata: { cas_service: 'https://example.com/app1/' },
        client_id: 'app1_client_id',
        client_secret: 'app1_client_secret'
      }
    ]);
}

function mockFetchAuthorizationCode () {
  return nock('https://fake-tenant.auth0.com')
    .post('/oauth/token', body =>
      body.code === 'foo' &&
      body.client_id === 'app1_client_id' &&
      body.client_secret === 'app1_client_secret' &&
      body.grant_type === 'authorization_code' &&
      /\/callback$/.test(body.redirect_uri));
}

function parseSuperRequestXml (res, done) {
  res.text = '';
  res.setEncoding('utf8');
  res.on('data', chunk => res.text += chunk);

  res.on('end', () => {
    try {
      var body = res.text && new xmldom.DOMParser().parseFromString(res.text);
    } catch (e) {
      var err = e;
      // issue #675: return the raw response if the response parsing fails
      err.rawResponse = res.text || null;
      // issue #876: return the http status code if the response parsing fails
      err.statusCode = res.statusCode;
    } finally {
      done(err, body);
    }
  });
}

function casErrorResponse (res) {
  const select = xpath.useNamespaces({ cas: 'http://www.yale.edu/tp/cas' });
  const errorCode = select('/cas:serviceResponse/cas:authenticationFailure/@code', res.body)[0].nodeValue;
  expect(errorCode).to.equal('SERVER_ERROR');
  const errorText = select('/cas:serviceResponse/cas:authenticationFailure/text()', res.body)[0].nodeValue;
  expect(errorText).to.match(/^Error ID \S+$/);
}

function casSuccessResponse (res) {
  const select = xpath.useNamespaces({ cas: 'http://www.yale.edu/tp/cas' });
  const user = select('/cas:serviceResponse/cas:authenticationSuccess/cas:user/text()', res.body)[0].nodeValue;
  expect(user).to.equal('foo@example.com');
  const emailAttribute = select('/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:email/text()', res.body)[0].nodeValue;
  expect(emailAttribute).to.equal('foo@example.com');
  const authenticationDateAttribute = select('/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:authenticationDate/text()', res.body)[0].nodeValue;
  expect(authenticationDateAttribute).to.not.be.empty;

  // uncomment to see actual XML
  // const serializer = new xmldom.XMLSerializer();
  // console.log('xml:', serializer.serializeToString(res.body));
}

function createIdToken (algorithm, secretOrPrivateKey, opts) {
  opts = opts || {};
  Object.assign(opts, {
    audience: 'app1_client_id',
    issuer: 'https://fake-tenant.auth0.com/',
    subject: 'auth0|1234',
    algorithm: algorithm
  })

  return jwt.sign({ email: 'foo@example.com' }, secretOrPrivateKey, opts);
}

function mockFetchJwks () {
  return nock('https://fake-tenant.auth0.com')
    .get('/.well-known/jwks.json');
}

function certToX5C (cert) {
  const oneLine = cert.replace(/\n/g, '');
  return /^-----BEGIN CERTIFICATE-----(\S+)-----END CERTIFICATE-----$/
    .exec(oneLine)[1];
}

// private / public key for RS256 tests
const privateKey = fs.readFileSync(path.join(__dirname, './rs256/private.key'), 'utf8');
const publicKey = certToX5C(fs.readFileSync(path.join(__dirname, './rs256/public.crt'), 'utf8'));

describe("CAS Server", () => {
  var app;

  beforeEach(() => {
    const configValues = {
      SESSION_SECRET: 'test secret',
      AUTH0_DOMAIN: 'fake-tenant.auth0.com',
      API_V2_CLIENT_ID: 'client_id',
      API_V2_CLIENT_SECRET: 'client_secret',
      AUTH0_CONNECTION: 'foo_connection',
      AUTH0_SCOPES: 'scope1 scope2',
      CAS_USERNAME_FIELD: 'email'
    };
    const config = key => configValues[key];

    app = server(config);
  });

  describe("GET /login", () => {
    it("should require the 'service' param", done => {
      request(app)
        .get('/login')
        .expect(400)
        .expect('Content-Type', /html/)
        .expect('Missing required parameter: service')
        .end(done);
    });

    it("should require a registered service", done => {
      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients()
      ];

      request(app)
        .get('/login?service=foo')
        .expect(400)
        .expect('Content-Type', /html/)
        .expect('Unrecognized service: foo')
        .end(err => {
          if (err) return done(err);

          interceptors.forEach(i => i.done());
          done();
        });
    });

    it("should redirect to Auth0 to start an OAuth2 authorization code flow", done => {
      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients()
      ];

      request(app)
        .get('/login?service=https://example.com/app1/')
        .expect(302)
        .expect(res => {
          const locationUrl = url.parse(res.headers.location, true);

          expect(locationUrl.protocol).to.equal('https:');
          expect(locationUrl.host).to.equal('fake-tenant.auth0.com');
          expect(locationUrl.pathname).to.equal('/authorize');
          expect(locationUrl.query.client_id).to.equal('app1_client_id');
          expect(locationUrl.query.response_type).to.equal('code');
          expect(locationUrl.query.scope).to.equal('scope1 scope2');
          expect(locationUrl.query.redirect_uri).to.match(/\/callback$/);
          expect(locationUrl.query.connection).to.equal('foo_connection');
          expect(locationUrl.query.state).to.exist;
        })
        .expect('Content-Type', /text\/plain/)
        .expect(/redirecting to/i)
        .end(err => {
          if (err) return done(err);

          interceptors.forEach(i => i.done());
          done();
        });
    });
  });

  describe("GET /callback", () => {
    it("should require the 'code' param", done => {
      request(app)
        .get('/callback?state=foo')
        .expect(400)
        .expect('Content-Type', /html/)
        .expect('Missing required parameter: code')
        .end(done);
    });

    it("should require the 'state' param", done => {
      request(app)
        .get('/callback?code=foo')
        .expect(400)
        .expect('Content-Type', /html/)
        .expect('Missing required parameter: state')
        .end(done);
    });

    it("should require that the 'state' param match the session that was started by '/login'", done => {
      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients()
      ];

      // start the flow by calling /login
      request(app)
        .get('/login?service=https://example.com/app1/')
        .end((err, res) => {
          if (err) return done(err);

          // capture cookies so that can be passed in subsequent requests
          const cookies = res.header['set-cookie'];

          // simulate the redirect to /callback from Auth0 with bad state
          request(app)
            .get('/callback?code=foo&state=bar')
            .set('cookie', cookies)
            .expect(400)
            .expect('Content-Type', /html/)
            .expect('Invalid session')
            .end(err => {
              if (err) return done(err);

              interceptors.forEach(i => i.done());
              done();
            });
        });
    });

    it("should redirect to the service, passing the CAS ticket", done => {
      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients()
      ];

      // start the flow by calling /login
      request(app)
        .get('/login?service=https://example.com/app1/')
        .end((err, res) => {
          if (err) return done(err);

          // capture cookies and state so they can be passed in subsequent requests
          const cookies = res.header['set-cookie'];
          const state = url.parse(res.header.location, true).query.state;

          // simulate the redirect to /callback from Auth0 with correct state
          request(app)
            .get('/callback?code=foo&state=' + state)
            .set('cookie', cookies)
            .expect(302)
            .expect(res => {
              const locationUrl = url.parse(res.headers.location, true);

              expect(locationUrl.protocol).to.equal('https:');
              expect(locationUrl.host).to.equal('example.com');
              expect(locationUrl.pathname).to.equal('/app1/');
              // the CAS ticket should be the same as the Auth0 authorization code
              expect(locationUrl.query.ticket).to.equal('foo');
            })
            .expect('Content-Type', /text\/plain/)
            .expect(/redirecting to/i)
            .end((err, res) => {
              if (err) return done(err);

              interceptors.forEach(i => i.done());
              done();
            });
        });
    });
  });

  describe("GET /p3/serviceValidate", () => {
    it("should require the 'service' param", done => {
      request(app)
        .get('/p3/serviceValidate?ticket=foo')
        .expect(400)
        .expect('Content-Type', /html/)
        .expect('Missing required parameter: service')
        .end(done);
    });

    it("should require the 'ticket' param", done => {
      request(app)
        .get('/p3/serviceValidate?service=bar')
        .expect(400)
        .expect('Content-Type', /html/)
        .expect('Missing required parameter: ticket')
        .end(done);
    });

    it("should require a registered service", done => {
      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients()
      ];

      request(app)
        .get('/p3/serviceValidate?service=bar&ticket=foo')
        .expect(400)
        .expect('Content-Type', /html/)
        .expect('Unrecognized service: bar')
        .end(err => {
          if (err) return done(err);

          interceptors.forEach(i => i.done());
          done();
        });
    });

    it("should return a CAS server error response if the Auth0 '/oauth/token' call results in an error", done => {
      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients(),
        mockFetchAuthorizationCode()
          .replyWithError('VOIP!')
      ];

      request(app)
        .get('/p3/serviceValidate?service=https://example.com/app1/&ticket=foo')
        .parse(parseSuperRequestXml)
        .expect(500)
        .expect('Content-Type', /application\/xml/)
        .expect(casErrorResponse)
        .end((err, res) => {
          if (err) return done(err);

          interceptors.forEach(i => i.done());
          done();
        });
    });

    it("should return an CAS 'invalid ticket' error response if the Auth0 '/oauth/token' call does not successfully return an id_token", done => {
      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients(),
        mockFetchAuthorizationCode()
          .reply(400, { description: 'nope!' })
      ];

      request(app)
        .get('/p3/serviceValidate?service=https://example.com/app1/&ticket=foo')
        .parse(parseSuperRequestXml)
        .expect(400)
        .expect('Content-Type', /application\/xml/)
        .end((err, res) => {
          if (err) return done(err);

          const select = xpath.useNamespaces({ cas: 'http://www.yale.edu/tp/cas' });
          const errorCode = select('/cas:serviceResponse/cas:authenticationFailure/@code', res.body)[0].nodeValue;
          expect(errorCode).to.equal('INVALID_TICKET');
          const errorText = select('/cas:serviceResponse/cas:authenticationFailure/text()', res.body)[0].nodeValue;
          expect(errorText).to.equal("({'description':'nope!'})");

          interceptors.forEach(i => i.done());
          done();
        });
    });

    it("should return a CAS server error response if the id_token can't be decoded", done => {
      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients(),
        mockFetchAuthorizationCode()
          .reply(200, { id_token: 'bad token' })
      ];

      request(app)
        .get('/p3/serviceValidate?service=https://example.com/app1/&ticket=foo')
        .parse(parseSuperRequestXml)
        .expect(500)
        .expect('Content-Type', /application\/xml/)
        .expect(casErrorResponse)
        .end((err, res) => {
          if (err) return done(err);

          interceptors.forEach(i => i.done());
          done();
        });
    });

    it("should return a CAS server error response if an HS256 id_token fails validation with the configured secret", done => {
      const idToken = createIdToken('HS256', 'another secret');

      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients(),
        mockFetchAuthorizationCode()
          .reply(200, { id_token: idToken })
      ];

      request(app)
        .get('/p3/serviceValidate?service=https://example.com/app1/&ticket=foo')
        .parse(parseSuperRequestXml)
        .expect(500)
        .expect('Content-Type', /application\/xml/)
        .expect(casErrorResponse)
        .end((err, res) => {
          if (err) return done(err);

          interceptors.forEach(i => i.done());
          done();
        });
    });

    it("should return a CAS success response with an HS256 id_token", done => {
      const idToken = createIdToken(
        'HS256',
        new Buffer('app1_client_secret', 'base64'));

      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients(),
        mockFetchAuthorizationCode()
          .reply(200, { id_token: idToken })
      ];

      request(app)
        .get('/p3/serviceValidate?service=https://example.com/app1/&ticket=foo')
        .parse(parseSuperRequestXml)
        .expect(200)
        .expect('Content-Type', /application\/xml/)
        .expect(casSuccessResponse)
        .end((err, res) => {
          if (err) return done(err);

          interceptors.forEach(i => i.done());
          done();
        });
    });

    it("should return a CAS server error response if an RS256 id_token's public key can't be fetched via the JWKS endpoint", done => {
      const idToken = createIdToken(
        'RS256',
        privateKey,
        { header: { kid: 'fake-tenant-kid' }});

      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients(),
        mockFetchAuthorizationCode()
          .reply(200, { id_token: idToken }),
        mockFetchJwks()
          .replyWithError('VOIP!')
      ];

      request(app)
        .get('/p3/serviceValidate?service=https://example.com/app1/&ticket=foo')
        .parse(parseSuperRequestXml)
        .expect(500)
        .expect('Content-Type', /application\/xml/)
        .expect(casErrorResponse)
        .end((err, res) => {
          if (err) return done(err);

          interceptors.forEach(i => i.done());
          done();
        });
    });

    it("should return a CAS server error response if an RS256 id_token fails validation with the configured public key", done => {
      const idToken = createIdToken(
        'RS256',
        privateKey,
        { header: { kid: 'fake-tenant-kid' }});

      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients(),
        mockFetchAuthorizationCode()
          .reply(200, { id_token: idToken }),
        mockFetchJwks()
          .reply(200, {
            keys: [
              {
                kid: 'fake-tenant-kid',
                alg: 'RS256',
                kty: 'RSA',
                use: 'sig',
                x5c: [ 'invalid_public_key' ]
              }
            ]
          })
      ];

      request(app)
        .get('/p3/serviceValidate?service=https://example.com/app1/&ticket=foo')
        .parse(parseSuperRequestXml)
        .expect(500)
        .expect('Content-Type', /application\/xml/)
        .expect(casErrorResponse)
        .end((err, res) => {
          if (err) return done(err);

          interceptors.forEach(i => i.done());
          done();
        });
    });

    it("should return a CAS success response with an RS256 id_token", done => {
      const idToken = createIdToken(
        'RS256',
        privateKey,
        { header: { kid: 'fake-tenant-kid' }});

      const interceptors = [
        mockFetchApiToken(),
        mockFetchClients(),
        mockFetchAuthorizationCode()
          .reply(200, { id_token: idToken }),
        mockFetchJwks()
          .reply(200, {
            keys: [
              {
                kid: 'fake-tenant-kid',
                alg: 'RS256',
                kty: 'RSA',
                use: 'sig',
                x5c: [ publicKey ]
              }
            ]
          })
      ];

      request(app)
        .get('/p3/serviceValidate?service=https://example.com/app1/&ticket=foo')
        .parse(parseSuperRequestXml)
        .expect(200)
        .expect('Content-Type', /application\/xml/)
        .expect(casSuccessResponse)
        .end((err, res) => {
          if (err) return done(err);

          interceptors.forEach(i => i.done());
          done();
        });
    });
  });
});
