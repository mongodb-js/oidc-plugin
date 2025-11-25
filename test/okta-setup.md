# Okta test setup steps

To reproduce the Okta test setup used by this package, perform the following steps.
Start with creating a **free integrator account** at https://developer.okta.com/signup/.

When you go to that page, make sure that you don't create an Auth0 free account,
but a **Free Integrator Account**.

## 1. Set up Okta application

1. In your Okta developer dashboard, select "Applications → Applications" in the sidebar
   1. Click "Create App Integration"
   1. Select "OIDC 1. OpenID Connect"
   1. Select "Native Application"
   1. Confirm creating the application
1. In the application creation screen:
   1. Give the application any name: _Copy the name, you'll need it later._
   1. In the "Grant Type" section, allow "Authorization Code", "Refresh Token", "Device Authorization"
   1. In the "Sign-in redirect URIs" section, allow the standardized redirect URL: "http://localhost:27097/redirect"
   1. In the "Controlled access" section, choose "Allow everyone in your organization to access"
   1. Save the application
1. In the application configuration screen:
   1. Ensure "Require PKCE as additional verification" is checked (it should be by default)
   1. Write down the "Client ID" value somewhere

## 2. Disable MFA for your test application

> With the latest Okta changes, all applications require MFA by default, and conveniently,
> it suggests Okta Verify. While this might be a good default for real applications, it breaks
> our tests that simulate human behaviour, as an application does not easily use MFA.

1. In the dashboard sidebar, go to "Security → Authentication Policies"
1. Click "App sign-in"
   1. On the right side, click "Create policy"
   1. Give it a name, like "No MFA"
1. It will automatically redirect to the Rules of the policy
   1. In the Catch-all Rule, click "Actions → Edit"
      1. In the modal, scroll down until you reach "User must authenticate with"
      1. In the dropdown, choose "Password" in the "1 factor type" section.
1. In the same page, click on Applications (just after `Rules (1)`)
   1. Click on "Add app" and choose your test application.

## 3. Set up Okta Authorization Server (AS)

1. In the dashboard sidebar, go to "Security → API"
1. Click "Add Authorization Server"
   1. Pick any name
   1. Copy the "Client ID" value from the previous step into the "Audience" field
   1. Click "Save"
1. In the Authorization Server configuration screen:
   1. Write down the first part of the URI listed under "Metadata URI", before
      the `.well-known` part (without a trailing slash). This value is now called the "Issuer URI"
   1. Go to the "Claims" tab, click "Add Claim"
      1. Name: Any name
      1. Include in token type: Access Token
      1. Value type: Groups
      1. Filter: Equals root
      1. Include in: Any scope
   1. Go to the "Access Policies" tab, click "Add Policy"
   1. Add a default policy with any name and description that applies to All Clients
      1. In the policy configuration, click "Add Rule" and add a rule with all settings set to defaults

## 4. Set up test group for user

1. In the sidebar, go to "Directory → Groups"
   1. Click "Add Group"
   1. Set the name "root"
   1. Click "Save"

## 5. Set up test user entry

1. In the sidebar, go to "Directory → People"
   1. Click "Add Person"
   1. Pick a username and primary email, e.g. "devtools-oidc-testuser@mongodb-dev.com"
   1. In groups, make sure to add the group "root".
   1. Click "I will set password" and disable "User must change password on first login"
   1. Set a random password
   1. Click "Save"

## 6. Create local Okta testing configuration

1. Store the [Issuer URI, Client ID] tuple as a JSON array of strings and
   store it in the `OKTA_TEST_CONFIG` environment variable
1. Store the [User email, Password] tuple similarly in the `OKTA_TEST_CREDENTIALS` variable
