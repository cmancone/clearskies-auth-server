# clearskies-auth-server

Contains the handlers needed to manage an authentication server with clearskies.

## Getting started

```
pip install clear-skies-auth-server
```

Click [here for a detailed usage example](https://github.com/cmancone/clearskies-auth-server-example).

## Overview

This package provides the various pieces needed to manage an authentication server.  Specifically, it authenticates users and issues signed JSON Web Tokens (JWTs) for other services to validate.  This is intended for use as a stand-alone identity provider (IdP) and so requires a datastore where users (and, if needed, passwords) are validated.  Naturally, the datastore is provided via a clearskies model, and thus this can work with a wide variety of backends.

In essence, you get to chose which parts of the auth server you need, provide a bit of configuration, and wrap the handlers up in a standard [clearskies SimpleRouting handler](https://clearskies.info/docs/handlers/simple-routing.html).  Naturally, clearskies will auto-generate your OAI3 docs for you.

Keep in mind that this is the backend API endpoints _only_.  You'll have to provide your own frontend.

## Handlers

The following handlers are provided by this package to expose the necessary parts of the authorization server:

 1. [generate-keys](#generate-keys)
 2. [jwks](#jwks)
 3. [password_login](#password-login)
 4. [password_less_email_request_login](#password-less-email-request-login)
 5. [password_less_validate_login](#password-less-validate-login)

Roadmap for 1.0:

 * MFA

### JWKS

This handler publishes the JSON Web Key Set (JWKS) that is necessary for JWT consumers to validate JWTs created by the service.

### Password Login

This manages password-based logins.

### Password-less Email Request Login

For a password-less login system, this allows a user to request a login.  Note that for minimalist systems, an explicit registration step is no longer required.

### Password-less Validate Login

Validates the login (and possibly completes registration) for a password-less login system.
