const Express = require('express');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const sessions = require('client-sessions');

const middleware = require('./middleware');
const cas = require('./cas');

module.exports = (config) => {
  const app = new Express();

  app.use(cookieParser());
  app.use(morgan('dev'));

  // configure encrypted session
  app.use(sessions({
    cookieName: 'cas-session',
    requestKey: 'session',
    secret: config('SESSION_SECRET'),
    duration: 24 * 60 * 60 * 1000,
    activeDuration: 1000 * 60 * 5
  }));

  // CAS server endpoints

  app.get('/login',
    middleware.requireParams(['service']),
    middleware.getService(config),
    cas.login(config));

  app.get('/callback',
    middleware.requireParams(['code', 'state']),
    cas.auth0Callback(config));

  app.get('/p3/serviceValidate',
    middleware.requireParams(['service', 'ticket']),
    middleware.getService(config),
    cas.validate(config));

  return app;
};
