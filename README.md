# Auth0 CAS Server

A simple CAS server that uses Auth0 as the backing IDP

## Auth0 Setup

Create a non-interactive client in Auth0 that the server can use to read client data with the following scopes:
* `read:clients`
* `read:client_keys`

## Local setup

`.env` file:
```
AUTH0_DOMAIN=your-tenant.auth0.com
API_V2_CLIENT_ID=non-interactive-client-client_id
API_V2_CLIENT_SECRET=non-interactive-client-client_secret
AUTH0_REDIRECT_URI=http://localhost:3000/callback
AUTH0_CONNECTION=connection-name
SECURE_COOKIE=false
```
