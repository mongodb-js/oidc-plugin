# Okta test setup steps

To reproduce the Okta test setup used by this package, perform the following steps.
Start with creating a developer account at https://developer.okta.com/signup/.

## 1. Set up Okta application

1. In your Okta developer dashboard, select "Applications → Applications" in the sidebar
   1. Click "Create App Integration"
   1. Select "OIDC 1. OpenID Connect"
   1. Select "Native Application"
   1. Confirm creating application
1. In the application creation screen:
   1. Give the application any name
   1. In the "Grant Type" section, allow "Authorization Code", "Refresh Token", "Device Authorization"
   1. In the "Sign-in redirect URIs" section, allow the standardized redirect URL
      ("http://localhost:27097/redirect" or whatever [MONGOSH-1394][] results in)
   1. In the "Controlled access" section, choose "Allow everyone in your organization to access"
   1. Save the application
1. In the application configuration screen:
   1. Ensure "Require PKCE as additional verification" is checked (should be by default)
   1. Write down the "Client ID" value somewhere

## 2. Set up Okta Authorization Server (AS)

1. In the dashboard sidebar, go to "Security → API"
1. Click "Add Authorization Server"
   1. Pick any name
   1. Copy the "Client ID" value from the previous step into the "Audience" field
   1. Click "Save"
1. In the Authorization Server configuration screen:
   1. Write down the first part of the URI listed under "Metadata URI", before
      the `.well-known` part (without a trailing slash). This value is now called "Issuer URI"
   1. Go to the "Claims" tab, click "Add Claim"
   1. Add a claim with the name "groups", included in access tokens, that evaluates to `{'root'}`
   1. Go to the "Access Policies" tab, click "Add Policy"
   1. Add a default policy with any name and description that applies to All Clients
      1. In the policy configuration, click "Add Rule" and add a rule with all settings set to defaults

## 3. Set up test user entry

1. In the sidebar, go to "Directory → People"
   1. Click "Add Person"
   1. Pick a username and primary email of e.g. "devtools-oidc-testuser@mongodb-dev.com"
   1. Click "I will set password" and disable "User must change password on first login"
   1. Set a random password and click "Save"

## 4. Create local Okta testing configuration

1. Store the [Issuer URI, Client ID] tuple as a JSON array of strings and
   store it in the `OKTA_TEST_CONFIG` environment variable
1. Store the [User email, Password] tuple similarly in the `OKTA_TEST_CREDENTIALS` variable

[mongosh-1394]: https://jira.mongodb.org/browse/MONGOSH-1394
