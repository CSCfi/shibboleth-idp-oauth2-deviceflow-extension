# OAuth 2.0 Device Authorization Grant

> **Note**
> This plugin is under construction and the features are still subject to change.
> The examples are not yet tested with the current code.

## Contents

- [Overview](#overview)
- [Plugin Installation](#plugin-installation)
  - [Dependencies](#dependencies)
  - [Installation example](#installation-example)
- [First installation, by example](#first-installation-by-example)
  - [Step 1: A confidential client](#step-1-a-confidential-client)
    - [Relying party](#relying-party)
    - [Client registration](#client-registration)
    - [Device authorization request](#device-authorization-request)
    - [User verification](#user-verification)
    - [Token request](#token-request)
  - [Step 2: Requesting an authentication method](#step-2-requesting-an-authentication-method)
  - [Step 3: Setting the verification URI](#step-3-setting-the-verification-uri)
    - [A short verification URI](#a-short-verification-uri)
    - [One client only](#one-client-only)
  - [Step 4: One token endpoint](#step-4-one-token-endpoint)
    - [Option 1: Publishing the token endpoint of the plugin](#option-1-publishing-the-token-endpoint-of-the-plugin)
    - [Option 2: Rewriting the OP token endpoint](#option-2-rewriting-the-op-token-endpoint)
- [Reference](#reference)
  - [Profile configuration settings](#profile-configuration-settings)
  - [Properties](#properties)
  - [Beans](#beans)
  - [Views](#views)

## Overview

Plugin that implements [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
(RFC 8628) for Shibboleth Identity Provider. A device with no browser or with limited input asks
the IdP for a device code and a user code. The user opens the verification URI on another device,
authenticates, enters the user code and approves. Meanwhile the device polls the token endpoint
with the device code and gets an access token once the user has approved.

The plugin is built on the OpenID Connect OP plugin. Its endpoints run on the abstract flows of the
OP, so client authentication, metadata lookup, intercepts, audit and metrics work as in the OP.

Three endpoints:

| Endpoint | Description |
|---|---|
| `/idp/profile/oauth2/devicegrant/authorize` | Device authorization endpoint, RFC 8628 section 3.1. |
| `/idp/profile/oauth2/devicegrant/authenticate` | Verification URI, the user enters the user code and approves. |
| `/idp/profile/oauth2/devicegrant/token` | Token endpoint, RFC 8628 section 3.4. Also the grants of the OP token endpoint. |

Things you need to know about this plugin:

- It works only with OIDC OP 4.3, see [Plugin Installation](#plugin-installation).
- The token endpoint is the OP 4.3.0 token endpoint with the device code grant added.

## Plugin Installation

> **Note**
> Install this plugin only on OIDC OP **4.3**, that is 4.3.0 and its patch releases. The token
> endpoint is a copy of the OP 4.3.0 token endpoint and the plugin uses classes and beans of that
> release. Other OP versions are not supported. It is tested with OP 4.3.1.

| Plugin | Plugin ID | Module(s) | Depends on | Bug Reporting |
|---|---|---|---|---|
| OAuth 2.0 Device Authorization Grant | `fi.csc.shibboleth.plugin.oauth2.devicegrant` | `idp.DeviceGrant` | `idp.oidc.OP.6` | janne.lauros@csc.fi |

Requires IdP **5.0.0** or later and OIDC OP **4.3**.

### Dependencies

> **Note**
> This plugin depends on the OpenID Connect OP plugin and on what that plugin depends on. You need
> to install them **first**, as
> [OIDC OP](https://shibboleth.atlassian.net/wiki/spaces/IDPPLUGINS/pages/1376878976/OIDC+OP)
> of the Shibboleth wiki tells.

### Installation example

The releases are on the [releases page](https://github.com/CSCfi/shibboleth-idp-oauth2-deviceflow-extension/releases)
of this repository.

The key that signed the releases is
[keys.txt](oauth2-devicegrant-dist/src/main/resources/bootstrap/keys.txt). It becomes the truststore
of the plugin.

<details>
<summary>Example installation of this plugin</summary>

```bash
cd /opt/shibboleth-idp

# The key that signed the distribution becomes the truststore of the plugin.
mkdir -p credentials/fi.csc.shibboleth.plugin.oauth2.devicegrant
wget -O credentials/fi.csc.shibboleth.plugin.oauth2.devicegrant/truststore.asc \
  https://raw.githubusercontent.com/CSCfi/shibboleth-idp-oauth2-deviceflow-extension/master/oauth2-devicegrant-dist/src/main/resources/bootstrap/keys.txt

# Install a release.
bin/plugin.sh \
  -i https://github.com/CSCfi/shibboleth-idp-oauth2-deviceflow-extension/releases/download/v1.0.0/shibboleth-idp-plugin-oauth2-devicegrant-1.0.0.tar.gz

# Later, update to the latest release.
bin/plugin.sh -u fi.csc.shibboleth.plugin.oauth2.devicegrant
```

</details>

Installing the plugin activates module `idp.DeviceGrant` and creates four files:

| File | Description |
|---|---|
| *conf/devicegrant.properties* | Every deployer-facing property. |
| *views/oauth2/devicegrant/authenticate-usercode.vm* | The page where the user enters the user code. |
| *views/oauth2/devicegrant/authenticate-userapproval.vm* | The page where the user approves or denies the device. |
| *views/oauth2/devicegrant/authenticate-end.vm* | The page shown after the decision. |

## First installation, by example

Step 1 sets up the device grant for one confidential client and goes through the grant with curl.
Step 2 adds a requested authentication method. Step 3 sets the verification URI shown to the user.
Step 4 makes the token endpoint of the plugin the only token endpoint of the OP.
The examples are from a test deployment so they fit
together, but it is not guaranteed that they work for you as such.

`https://idp.example.org` is your IdP everywhere below.

### Step 1: A confidential client

#### Relying party

**File(s):** *conf/relying-party.xml*
**Format:** Native Spring

The device authorization and user verification endpoints are enabled with **OAUTH2.DeviceGrant**.
The token endpoint uses **OAUTH2.Token** of the OP, with the device code grant added to its
`grantTypes`. The device clients are registered clients, so both go to the default relying party:

<details>
<summary>conf/relying-party.xml</summary>

```xml
<bean id="shibboleth.DefaultRelyingParty" parent="RelyingParty">
    <property name="profileConfigurations">
        <list>
            <!-- Device authorization and user verification endpoints of the device grant -->
            <ref bean="OAUTH2.DeviceGrant" />
            <!-- Token endpoint, the device code grant enabled -->
            <bean parent="OAUTH2.Token"
                p:grantTypes="authorization_code,refresh_token,urn:ietf:params:oauth:grant-type:device_code" />
        </list>
    </property>
</bean>
```

Full file: [conf/relying-party.xml](docs/example/step-1/conf/relying-party.xml)

</details>

Instead of `p:grantTypes` you can add the grant type for all relying parties with property
`idp.oauth2.grantTypes` of the OP in *conf/oidc.properties*.

#### Client registration

**File(s):** *metadata/oidc-client.json*
**Format:** JSON

The device is registered as an OIDC client of the OP. The client has to have the device grant in
its `grant_types`, and the scopes it may ask in `scope`:

<details>
<summary>metadata/oidc-client.json</summary>

```json
[
  {
    "client_id": "device-client",
    "client_name": "Device client",
    "client_secret": "CHANGE-ME",
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid profile",
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"]
  }
]
```

Full file: [metadata/oidc-client.json](docs/example/step-1/metadata/oidc-client.json)

</details>

#### Device authorization request

The device asks for a device code and a user code:

```bash
curl -u device-client:CHANGE-ME \
  -d "scope=openid profile" \
  https://idp.example.org/idp/profile/oauth2/devicegrant/authorize
```

```json
{
  "device_code": "bea82bb44bf1f56d0c3e7a91d45f2b86e19c0d7a",
  "user_code": "WDJBMJHT",
  "verification_uri": "https://idp.example.org/idp/profile/oauth2/devicegrant/authenticate",
  "verification_uri_complete": "https://idp.example.org/idp/profile/oauth2/devicegrant/authenticate?user_code=WDJBMJHT",
  "expires_in": 600,
  "interval": 5
}
```

The scope is checked against the `scope` of the client, as the OP does. A scope the client may not
ask is left out. With strict scope validation of the OP the request fails with `invalid_scope`.

#### User verification

The user opens `verification_uri` and enters the user code, or opens `verification_uri_complete`
that has the code already. The case of the letters does not matter and dashes and spaces are
ignored. The user authenticates and approves or denies. A user code can be used once.

#### Token request

The device polls the token endpoint with the device code, at most every `interval` seconds:

```bash
curl -u device-client:CHANGE-ME \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=bea82bb44bf1f56d0c3e7a91d45f2b86e19c0d7a" \
  https://idp.example.org/idp/profile/oauth2/devicegrant/token
```

Before the user has approved:

```json
{
  "error": "authorization_pending",
  "error_description": "The authorization request is still pending as the end user hasn't yet completed the user interaction steps"
}
```

After the user has approved:

```json
{
  "access_token": "AAdzZWNyZXQxay3BFeqTrQljaM4iIeDvxwbu...",
  "token_type": "Bearer",
  "expires_in": 600,
  "id_token": "eyJhbGciOiJFUzI1NiJ9..."
}
```

A device polling faster than `interval` gets `slow_down`, and from then on it has to wait 5 seconds
longer between requests, as RFC 8628 section 3.5 says. Each further early request adds another 5
seconds.

The device code gives one token response. A second request with the same device code gets
`invalid_grant`, as does a request from another client than the one the device code was issued to.
If the user denied, the error is `access_denied`. After the device code has expired it is
`expired_token`.

With `scope=openid` in the device authorization request the response has an `id_token` as well.

### Step 2: Requesting an authentication method

**File(s):** *conf/authn/authn.properties*
**Format:** Java properties

The device can ask how the user is authenticated with `acr_values`. There has to be an
authentication flow that supports a principal of that value. The plugin treats the requested values
always as essential. In the example the Password flow is enabled and supports the value
`https://example.org/acr/password`:

<details>
<summary>conf/authn/authn.properties</summary>

```properties
idp.authn.flows = Password
idp.authn.Password.supportedPrincipals = \
    saml2/urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport, \
    saml2/urn:oasis:names:tc:SAML:2.0:ac:classes:Password, \
    saml1/urn:oasis:names:tc:SAML:1.0:am:password, \
    oidc/https://example.org/acr/password
```

Full file: [conf/authn/authn.properties](docs/example/step-2/conf/authn/authn.properties)

</details>

```bash
curl -u device-client:CHANGE-ME \
  -d "scope=openid profile" \
  -d "acr_values=https://example.org/acr/password" \
  https://idp.example.org/idp/profile/oauth2/devicegrant/authorize
```

### Step 3: Setting the verification URI

The verification URI is what the device shows to the user, as `verification_uri` and, with the user
code added, `verification_uri_complete`. Without a setting the plugin builds it from the host, port
and context path of the device authorization request, so
`https://idp.example.org/idp/profile/oauth2/devicegrant/authenticate`.

#### A short verification URI

**File(s):** *conf/devicegrant.properties*, *etc/jetty-rewrite-rules.xml* of the Jetty base
**Format:** Java properties, Jetty XML

A user types the verification URI from the screen of the device, so a short one helps. Set it as
the verification URI:

<details>
<summary>conf/devicegrant.properties</summary>

```properties
devicegrant.verificationURI = https://idp.example.org/shortExample
```

Full file: [conf/devicegrant.properties](docs/example/step-3/conf/devicegrant.properties)

</details>

Redirect it in Jetty to the user verification endpoint and keep the query string, it has the user
code of `verification_uri_complete`. Enable the `rewrite` module of Jetty and add the rule:

<details>
<summary>etc/jetty-rewrite-rules.xml</summary>

```xml
<?xml version="1.0"?>
<!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "https://jetty.org/configure_10_0.dtd">
<Configure id="Rewrite" class="org.eclipse.jetty.rewrite.handler.RuleContainer">
  <Call name="addRule">
    <Arg>
      <New class="org.eclipse.jetty.rewrite.handler.RedirectRegexRule">
        <Set name="regex">^/shortExample$</Set>
        <Set name="matchQuery">false</Set>
        <Set name="addQueries">true</Set>
        <Set name="location">/idp/profile/oauth2/devicegrant/authenticate</Set>
      </New>
    </Arg>
  </Call>
</Configure>
```

Full file: [etc/jetty-rewrite-rules.xml](docs/example/step-3/jetty-base/etc/jetty-rewrite-rules.xml)

</details>

The device authorization response is then:

```json
{
  "device_code": "bea82bb44bf1f56d0c3e7a91d45f2b86e19c0d7a",
  "user_code": "WDJBMJHT",
  "verification_uri": "https://idp.example.org/shortExample",
  "verification_uri_complete": "https://idp.example.org/shortExample?user_code=WDJBMJHT",
  "expires_in": 600,
  "interval": 5
}
```

#### One client only

**File(s):** *conf/relying-party.xml*
**Format:** Native Spring

`verificationURI` is a setting of **OAUTH2.DeviceGrant**, so it can be set for one client in a
relying party override:

<details>
<summary>conf/relying-party.xml</summary>

```xml
<util:list id="shibboleth.RelyingPartyOverrides">
    <bean parent="RelyingPartyByName" c:relyingPartyIds="device-client">
        <property name="profileConfigurations">
            <list>
                <bean parent="OAUTH2.DeviceGrant" p:verificationURI="https://idp.example.org/shortExample" />
                <bean parent="OAUTH2.Token"
                    p:grantTypes="authorization_code,refresh_token,urn:ietf:params:oauth:grant-type:device_code" />
            </list>
        </property>
    </bean>
</util:list>
```

Full file: [conf/relying-party.xml](docs/example/step-3/conf/relying-party.xml)

</details>

### Step 4: One token endpoint

Do this only when the device clients cannot be configured with the token endpoint of the plugin
while the other clients keep the OP token endpoint.

> **Note**
> The token endpoint of the plugin is a copy of the token endpoint of OP 4.3.0 with the device code
> grant added. When all clients use it, fixes to the token endpoint in later OP releases, security
> fixes included, do not reach any client until a release of this plugin is built on that OP. Until
> then all clients run the token endpoint of OP 4.3.0, whatever OP version is installed.

The token endpoint of the plugin handles the grants of the OP token endpoint too:
`authorization_code`, `refresh_token`, `client_credentials` and the device code grant. All of them
use **OAUTH2.Token**. So one token endpoint can serve all clients. The plugin does not publish
anything. There are two ways to have the clients use the token endpoint of the plugin, choose one:

- [Option 1: Publishing the token endpoint of the plugin](#option-1-publishing-the-token-endpoint-of-the-plugin):
  the discovery document names the token endpoint of the plugin. Clients that read the discovery
  document use it.
- [Option 2: Rewriting the OP token endpoint](#option-2-rewriting-the-op-token-endpoint): the
  discovery document keeps the OP token endpoint and Jetty passes its requests to the token
  endpoint of the plugin. All clients use it, also those with the OP token endpoint configured.

#### Option 1: Publishing the token endpoint of the plugin

**File(s):** *static/openid-configuration.json*
**Format:** JSON

Set the token endpoint of the plugin as `token_endpoint` of the discovery document of the OP:

```json
"token_endpoint": "https://idp.example.org/idp/profile/oauth2/devicegrant/token",
```

The OP token endpoint `/idp/profile/oidc/token` answers still, for clients that have its address
configured.

#### Option 2: Rewriting the OP token endpoint

**File(s):** *etc/jetty-rewrite-rules.xml* of the Jetty base, *conf/oidc.properties*
**Format:** Jetty XML, Java properties

When `token_endpoint` has to stay `https://idp.example.org/idp/profile/oidc/token`, rewrite it in
Jetty to the token endpoint of the plugin. Enable the `rewrite` module of Jetty and add the rule:

<details>
<summary>etc/jetty-rewrite-rules.xml</summary>

```xml
<?xml version="1.0"?>
<!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "https://jetty.org/configure_10_0.dtd">
<Configure id="Rewrite" class="org.eclipse.jetty.rewrite.handler.RuleContainer">
  <Call name="addRule">
    <Arg>
      <New class="org.eclipse.jetty.rewrite.handler.RewritePatternRule">
        <Set name="pattern">/idp/profile/oidc/token</Set>
        <Set name="replacement">/idp/profile/oauth2/devicegrant/token</Set>
      </New>
    </Arg>
  </Call>
</Configure>
```

</details>

After the rewrite the IdP sees the request URL of the plugin, while the client signs the URL it
called:

- **DPoP.** The `htu` claim of a DPoP proof is the URL the client called. Set the DPoP proof claims
  validator of the plugin to **OAUTH2.Token**, it accepts the OP token endpoint URL as `htu` at the
  token endpoint of the plugin. Property `devicegrant.token.endpointReplacement` is the path of the OP
  token endpoint, `/profile/oidc/token` by default. A relying party override with its own
  **OAUTH2.Token**, as in [One client only](#one-client-only), needs the validator too.
- **JWT client authentication.** The `aud` of a `client_secret_jwt` or `private_key_jwt` assertion
  is the issuer or the token endpoint URL. The issuer is always accepted. For the token endpoint
  URL add the token endpoint of the plugin to the endpoints of the OP that accept the OP token
  endpoint URL:

<details>
<summary>conf/relying-party.xml</summary>

```xml
<bean parent="OAUTH2.Token"
    p:grantTypes="authorization_code,refresh_token,urn:ietf:params:oauth:grant-type:device_code"
    p:dpopProofClaimsValidator-ref="devicegrant.DPoPProofClaimsValidator" />
```

</details>

<details>
<summary>conf/oidc.properties</summary>

```properties
idp.oauth2.jwtAuth.audienceValidator.endpointTargets = /profile/oauth2/introspection,/profile/oauth2/revocation,/profile/oauth2/pushed-authorization,/profile/oauth2/devicegrant/token
```

</details>

## Reference

### Profile configuration settings

**File(s):** *conf/relying-party.xml*
**Format:** Native Spring

#### OAUTH2.DeviceGrant

Endpoints `/idp/profile/oauth2/devicegrant/authorize` and `/idp/profile/oauth2/devicegrant/authenticate`,
profile ID `http://csc.fi/ns/profiles/oauth.net/2/device-flow`.

The bean has parent **AbstractOIDCSSOProfile** of the OIDC Config plugin, so the settings of that
parent apply as well. **OAUTH2.DeviceGrant.MDDriven** is the metadata-driven variant.

| Name | Type | Default | Description |
|---|---|---|---|
| `deviceCodeLength` | Integer | `40` | Length of the device code in hexadecimal characters, from 32 to 64. Property `devicegrant.deviceCode.defaultLength`. |
| `userCodeLength` | Integer | `8` | Length of the user code, at least 6. Property `devicegrant.userCode.defaultLength`. |
| `deviceCodeLifetime` | Duration | `PT10M` | Lifetime of the device code and the user code. Property `devicegrant.deviceCode.defaultLifetime`. |
| `pollingInterval` | Duration | `PT5S` | `interval` of the device authorization response. Property `devicegrant.pollingInterval`. |
| `verificationURI` | String | | Verification URI of the device authorization response. Built from the request when not set. Property `devicegrant.verificationURI`. |
| `tokenEndpointAuthMethods` | Collection&lt;String&gt; | | Of the OP plugin. Client authentication methods accepted. |
| `inboundInterceptorFlows` | List&lt;String&gt; | | Interceptor flows run after the request is decoded. |
| `outboundInterceptorFlows` | List&lt;String&gt; | | Interceptor flows run before the response is sent. Not run by the user verification endpoint. |
| `postAuthenticationFlows` | List&lt;String&gt; | | Interceptor flows run after the user has authenticated at the user verification endpoint, consent for instance. |
| `messageHandler` | Function&lt;MessageContext,Exception&gt; | | Of the OP plugin. Runs on the inbound message before authentication and on the outbound one before encoding. |

#### OAUTH2.Token

Endpoint `/idp/profile/oauth2/devicegrant/token` uses **OAUTH2.Token** of the OIDC Config plugin,
its settings are those of the OP token endpoint. Add `urn:ietf:params:oauth:grant-type:device_code` to
its `grantTypes`.

The plugin defines bean **devicegrant.DPoPProofClaimsValidator** for its `dpopProofClaimsValidator`
setting: the DPoP proof claims validators of the OP, with `htu` also accepted as the OP token
endpoint URL. See [Option 2: Rewriting the OP token endpoint](#option-2-rewriting-the-op-token-endpoint).

### Properties

**File(s):** *conf/devicegrant.properties*
**Format:** Java properties

| Name | Default | Description |
|---|---|---|
| `devicegrant.deviceCode.defaultLength` | `40` | Default of `deviceCodeLength`. |
| `devicegrant.userCode.defaultLength` | `8` | Default of `userCodeLength`. |
| `devicegrant.deviceCode.defaultLifetime` | `PT10M` | Default of `deviceCodeLifetime`. |
| `devicegrant.pollingInterval` | `PT5S` | Default of `pollingInterval`. |
| `devicegrant.verificationURI` | | Default of `verificationURI`. |
| `devicegrant.deviceCodeCache.StorageService` | `shibboleth.StorageService` | Storage of the device codes. Has to be server-side. |
| `devicegrant.authn.flows` | `OAuth2Client` | Client authentication flows of the device authorization endpoint, a regular expression. |
| `devicegrant.logging.authorize` | `OAuth2.DeviceAuthorization` | Logging id of the device authorization endpoint. |
| `devicegrant.logging.authenticate` | `OAuth2.DeviceVerification` | Logging id of the user verification endpoint. |
| `devicegrant.requestParser.DeviceAuthorizationRequest` | | Bean id of a custom request parser of the device authorization endpoint. |
| `devicegrant.requestParser.DeviceAuthenticationRequest` | | Bean id of a custom request parser of the user verification endpoint. |
| `devicegrant.token.endpointReplacement` | `/profile/oidc/token` | Path of the OP token endpoint. A DPoP proof with `htu` of it is accepted at the token endpoint of the plugin. |

### Beans

**File(s):** *conf/global.xml*
**Format:** Native Spring

You define these to change the defaults.

| Name | Type | Description |
|---|---|---|
| **devicegrant.authorize.MappedErrors** | Map&lt;String,ErrorObject&gt; | Errors of the device authorization endpoint by event. Default **shibboleth.oidc.DefaultApiMappedErrors** of the OP. |
| **shibboleth.oidc.token.MappedErrors** | Map&lt;String,ErrorObject&gt; | Of the OP. Errors of the token endpoint by event. Default **devicegrant.DefaultTokenMappedErrors**, the OP defaults and the device grant errors. Define it with parent **devicegrant.DefaultTokenMappedErrors** to keep the device grant errors. |
| **devicegrant.AllowedScopeStrategy** | Function | Scopes the client may ask at the device authorization and user verification endpoints. Default **shibboleth.oidc.DefaultAllowedScopeStrategy** of the OP, the `scope` of the client metadata. At the token endpoint **shibboleth.oidc.AllowedScopeStrategy** of the OP applies. |

### Views

**File(s):** *views/oauth2/devicegrant/*
**Format:** Velocity

| File | Description |
|---|---|
| *authenticate-usercode.vm* | The user enters the user code. Field `j_usercode`. |
| *authenticate-userapproval.vm* | The user approves (`_eventId_proceed`) or denies (`_eventId_deny`). Shows `client_name` of the client. |
| *authenticate-end.vm* | Shown after the decision. Shows `client_name` of the client. |

The views use message keys `idp.login.usercode*`, `idp.login.device.*` and `idp.device.*` with an English
default. You add translations to *messages/messages.properties*.
