# Rate Limiting OIDC 
This example shows you how to use Golang to login to your application with an Okta Hosted Login page.  The login is achieved through the [authorization code flow](https://developer.okta.com/authentication-guide/implementing-authentication/auth-code), where the user is redirected to the Okta-Hosted login page.  After the user authenticates they are redirected back to the application with an access code that is then exchanged for an access token.

This repository uses https://github.com/okta/samples-golang as a starting point.

![ezgif com-gif-maker (1)](https://user-images.githubusercontent.com/5663078/144407294-6f6bd4e7-32a0-4b5e-82a4-81370fba1e0f.gif)

## Authentication and Authorisation 
This POC uses Okta OIDC to perform authentication and [casbin](https://github.com/casbin/casbin) to perform RBAC Authorisation using the user's globalGroups. 

These are the allowed groups:
- "10gen-cloud": The user inside this group is an Admin
- "10gen-cloud-rate-limiting-read-only": The user inside this group has read-only access to their profile

## Prerequisites

Before running this sample, you will need the following:

* A valid user on [mongodb-qa.oktapreview.com](https://wiki.corp.mongodb.com/pages/viewpage.action?spaceKey=MMS&title=Cloud+IAM%27s+Okta+Usage)
* An Okta Application, configured for Web mode. This is done from the Okta Console and you can find instructions [here](https://developer.okta.com/docs/guides/sign-into-web-app/aspnet/main/#create-an-okta-app-integration).  When following the wizard, use the default properties

## Running This Example

```bash
git clone git@github.com:andreaangiolillo/rate-limiting-oidc.git
cd rate-limiting-oidc
```

Then install dependencies:
```bash
make setup
```

You also need to gather the following information from the Okta Developer Console:
- **Client ID** and **Client Secret** - These can be found on the "General" tab of the Web application that you created earlier in the Okta Developer Console.
- **Issuer** - This is the URL of the authorization server that will perform authentication.  We use https://mongodb-qa.oktapreview.com/oauth2/default.

Now that you have the information that you need, you can fill `.env` with them or defining the env variables  `CLIENT_ID`, `CLIENT_SECRET` and `ISSUER`.

```bash
CLIENT_ID={clientId}
CLIENT_SECRET={clientSecret}
ISSUER=https://mongodb-qa.oktapreview.com/oauth2/default
```

Start the app server:

```
go run main.go
```

Now navigate to http://localhost:8080 in your browser.

If you see a home page that prompts you to login, then things are working!  Clicking the **Log in** button will redirect you to the Okta hosted sign-in page.

You can login with the same account that you created when signing up for [mongodb-qa.oktapreview.com](https://wiki.corp.mongodb.com/pages/viewpage.action?spaceKey=MMS&title=Cloud+IAM%27s+Okta+Usage), or you can use a known username and password from your Okta Directory.

**Note:** 
If you are currently using your Developer Console, you already have a Single Sign-On (SSO) session for your Org.  You will be automatically logged into your application as the same user that is using the Developer Console.  
**You may want to use an incognito tab to test the flow from a blank slate.**

## Useful Resources
- [Casbin and Multi-Threading](https://casbin.org/docs/en/multi-threading)
- [Casbin - RBAC API](https://casbin.org/docs/en/rbac-api)
- [Casbin - Admin UI](https://casbin.org/docs/en/admin-portal)
- [OKTA - Create an app integration](https://developer.okta.com/docs/guides/sign-into-web-app/aspnet/main/#create-an-okta-app-integration)
- [OKTA - OIDC API](https://developer.okta.com/docs/reference/api/oidc/)
- [OKTA - Authorization Code Flow](https://developer.okta.com/authentication-guide/implementing-authentication/auth-code)
