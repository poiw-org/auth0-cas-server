# Auth0 CAS Server

A simple CAS server that uses Auth0 as the backing IDP

## Auth0 Setup

### Non-Interactive Client

Create a non-interactive client in Auth0 that the server can use to read client data with the following scopes:
* `read:clients`
* `read:client_keys`

Capture the Client ID and Client Secret of this client as it will be used in the next step (`API_V2_CLIENT_ID` and `API_V2_CLIENT_SECRET`).

### CAS Service Clients

Define one or more clients in Auth0 that will represent your CAS Services. To signify a client as a CAS Service, set the following **Application Metadata** item:

* `cas_service`: The identifier of the CAS Service which is also the URL that the server will redirect to once authentication is complete.

## Local setup

### Create an `.env` file:
```
AUTH0_DOMAIN=your-tenant.auth0.com
API_V2_CLIENT_ID=non-interactive-client-client_id
API_V2_CLIENT_SECRET=non-interactive-client-client_secret
AUTH0_CONNECTION=connection-name
SECURE_COOKIE=false
```

### Run
```sh
node index.js
```

### Perform a login flow

```
http://localhost:3000/login?service=SERVICE
```

where:
* `SERVICE` is one of the CAS Service identifiers you configured in the [CAS Service Clients](#cas-service-clients) section.

## Deploy as a Webtask

### Prerequisites

Make sure you have the following command-line dependencies installed:
* [Webtask CLI](https://github.com/auth0/wt-cli)  
  > NOTE: Follow [these steps](https://manage.auth0.com/#/account/webtasks) to set up a webtask profile that will deploy the webtask to your Auth0 tenant's container
* [Webtask Bundler](https://github.com/auth0/webtask-bundle)

Capture your webtask profile that you set up above:
```sh
WT_PROFILE=your-wt-profile
```

Finally make sure you've created the `.env` file described in the [Local setup](#local-setup) section.

### Deploy

```sh
./deploy $WT_PROFILE
```

### Perform a login flow

```
https://WEBTASK_CONTAINER_DOMAIN/cas_server/login?service=SERVICE
```

where:
* `WEBTASK_CONTAINER_DOMAIN` is the domain of your webtask container (which you see in the output of the `deploy` command above)
* `SERVICE` is one of the CAS Service identifiers you configured in the [CAS Service Clients](#cas-service-clients) section.
