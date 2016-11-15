require('dotenv').config();

const server = require('./server');
// config just returns contents of process.env
const config = (key) => process.env[key];
const app = server(config);

const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log(`Example app listening on port ${PORT}.`);
});
