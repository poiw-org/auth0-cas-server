const tools = require('auth0-extension-express-tools');
const server = require('./src/server');

module.exports = tools.createServer((config) => {
  return server(config);
});
