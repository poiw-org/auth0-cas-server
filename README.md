# Auth0 CAS Server

A simple [CAS](https://en.m.wikipedia.org/wiki/Central_Authentication_Service) server that uses Auth0 as the backing IDP.

## Overview

Presently Auth0 natively supports three authentication _protocols_ for your applications: [OpenID Connect](https://auth0.com/docs/protocols/oidc), [SAML](https://auth0.com/docs/protocols/saml), and [WS-Federation](https://auth0.com/docs/protocols/ws-fed) (we support many more for your backing IDPs). However, there are many applications that use CAS (Central Authentication Service) to perform authentication and SSO.

This sample demonstrates a simple service written in Node.js that acts as a protocol translator between CAS and Auth0 (using OpenID Connect). This allows an application that only knows how to interact with a CAS server to leverage all of the capabilities of Auth0 as an IDP (SSO, federation with other IDPs like social and enterprise, security, etc).

And to make it really easy, the sample includes steps to deploy the service as a [Webtask](https://webtask.io)!

## How it works

This CAS server implementation takes advantage of the fact that both OpenID Connect and CAS are redirect-based protocols using the browser. Therefore applications doesn't know or care that the CAS server has redirected the user to a different website (Auth0) to perform the actual authentication. All that matters is that the CAS protocol itself is honored between the application and the CAS Server.

Another implementation detail is that the CAS Server is completely stateless. To manage browser session it uses an [encrypted cookie](https://github.com/mozilla/node-client-sessions). It also reuses the Auth0 `code` value as the CAS `ticket` so there's no need to temporarily store a user's profile. The CAS `ticket` is intended to be single-use, which works seamlessly with the Auth0 `code`, which is also single-use.

## Flow

1. An application (aka CAS service) determines that the user needs to authenticate (eg. it detects there is no local session), so it redirects the browser to the CAS [Login endpoint](https://apereo.github.io/cas/4.2.x/protocol/CAS-Protocol-Specification.html#login-as-credential-requestor), passing the `service` parameter, which identifies the application:  

  ```
  Application redirect ->
  https://AUTH0_CAS_SERVER/login?service=SERVICE
  ```

2. The CAS Server verifies that the `SERVICE` identifier points to a [registered CAS service](#cas-service-clients). If so, it performs an OpenID Connect authorization code flow with Auth0, redireting to the `/authorize` endpoint:  

  ```
  CAS Server redirect ->
  https://AUTH0_DOMAIN/authorize?client_id=SERVICE_CLIENT_ID&response_type=code&scope=openid%20profile&redirect_uri=https://AUTH0_CAS_SERVER/callback&connection=AUTH0_CONNECTION&state=1234abcd
  ```

3. The user logs into the IDP of whatever connection was configured (`AUTH0_CONNECTION`) and Auth0 redirects back to the CAS Server callback, providing an OAuth2 `code` and `state`:  

  ```
  Auth0 redirect ->
  https://AUTH0_CAS_SERVER/callback?code=4242xyz&state=1234abcd
  ```

4. The CAS Server then redirects back to the application passing the `code` received by Auth0 as the CAS `ticket`:  

  ```
  Auth0 redirect ->
  https://example.com/app?ticket=4242xyz
  ```

5. Now the application can perform a server-to-server call to the CAS [Validate endpoint](https://apereo.github.io/cas/4.2.x/protocol/CAS-Protocol-Specification.html#p3servicevalidate-cas-30) to exchange the CAS `ticket` for the authenticated user profile:  

  ```
  Application:
  GET https://AUTH0_CAS_SERVER/p3/serviceValidate?service=SERVICE&ticket=4242xyz
  ```

6. Under the hood, the CAS Server calls the Auth0 `/oauth/token` endpoint to complete the OpenID Connection authorization code flow:  

  ```
  CAS Server:
  POST https://AUTH0_DOMAIN/oauth/token
  {
    "code": "CAS TICKET",
    "client_id": "AUTH0_CLIENT_ID",
    "client_secret": "AUTH0_CLIENT_SECRET",
    "grant_type": "authorization_code",
    "redirect_uri": "https://AUTH0_CAS_SERVER/callback"
  }
  ```

7. Auth0 responds with an `id_token` which contains the claims that are used to generate the expected user profile CAS response:  

  ```xml
  <?xml version="1.0"?>
  <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
    <cas:authenticationSuccess>
      <cas:user>user1@example.com</cas:user>
      <cas:attributes>
        <cas:email>user1@example.com</cas:email>
        <cas:email_verified>false</cas:email_verified>
        ...
      </cas:attributes>
    </cas:authenticationSuccess>
  </cas:serviceResponse>
  ```

  > NOTE: The CAS Server can also return JSON if the `Accept: applicaiton/json` header is passed.

## Auth0 Setup

### Non-Interactive Client

Create a **Non Interactive Client** in Auth0 that the server can use to read client data. Configure the client so its authorized to call the **Auth0 Management API** with the following scopes:

* `read:clients`
* `read:client_keys`

Capture the Client ID and Client Secret of this client as it will be used in the next step (`API_V2_CLIENT_ID` and `API_V2_CLIENT_SECRET`).

### CAS Service Clients

Create one or more clients in Auth0 that will represent your CAS Services. To signify a client as a CAS Service, add the following **Application Metadata** item:

* `cas_service`: The identifier of the CAS Service which is also the URL that the server will redirect to once authentication is complete.

## Local setup

### Create an `.env` file:
```
AUTH0_DOMAIN=your-tenant.auth0.com
API_V2_CLIENT_ID=non-interactive-client-client_id
API_V2_CLIENT_SECRET=non-interactive-client-client_secret
AUTH0_CONNECTION=connection-name
AUTH0_SCOPES="openid profile"
SECURE_COOKIE=false
SESSION_SECRET=a-hard-to-guess-secret
CAS_USERNAME_FIELD=auth0-user-profile-field-like-email
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

When the browser flow is complete you will be redirected back to your service's URL with a ticket query param:

```
SERVICE?ticket=TICKET
```

where:
* `SERVICE` is the CAS Service identifier used to begin the flow
* `TICKET` is the CAS ticket generated for the authentication transaction

You can then call the validate endpoint to obtain the authenticated user profile:

```sh
curl "http://localhost:3000/p3/serviceValidate?service=SERVICE&ticket=TICKET"
```

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

Finally make sure you've created the `.env` file described in the [Local setup](#local-setup) section as the script below will use it to configure secrets in the webtask.

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

The remaining steps are identical to those in the [Local setup](#local-setup) except calls are made against the webtask host.

## Contributors

Check them out [here](https://github.com/auth0-samples/auth0-cas-server/graphs/contributors)

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](https://auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
