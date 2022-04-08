const Express = require('express');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const sessions = require('client-sessions');

const middleware = require('./middleware');
const cas = require('./cas');

module.exports = (config, cache) => {
  // default cache has non-expiring keys
  cache = cache || {
      get: function (key) { return this.key; },
      set: function (key, value) { this.key = value; }
    };

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
    middleware.getService(config, cache),
    cas.login(config));

  app.get('/logout', (req,res)=>res.redirect(`https://${config("AUTH0_DOMAIN")}/v2/logout`));


  app.get('/p3/serviceValidate',
    middleware.requireParams(['service', 'ticket']),
    middleware.getService(config, cache),
    cas.validate(config, cache));

  // Auth0 callback

  app.get('/callback',
    middleware.requireParams(['code', 'state']),
    (req, res) => {
      // validate session
      if (req.session.state !== req.query.state)
        return res.status(400).send(`Το αίτημα σύνδεσης έληξε. Παρακαλώ προσπαθήστε να συνδεθείτε ξανά από την εφαρμογή που θέλετε να χρησιμοποιήσετε.`);

      // redirect to service, using Auth0 authorization code as CAS ticket
      res.redirect(`${req.session.serviceUrl.replace(":80",":443")}?ticket=${req.query.code}`);
    });

  return app;
};
