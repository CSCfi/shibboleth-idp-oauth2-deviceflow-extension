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

This plugin implements the [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
(RFC 8628) for Shibboleth Identity Provider. A device with no browser or limited input requests a
device code and a user code from the IdP. The user opens the verification URI on another device,
authenticates, enters the user code, and approves the request. Meanwhile, the device polls the token
endpoint with the device code until the user approves the request and the device receives an access token.

The plugin builds on the OpenID Connect OP plugin. Its endpoints use the OP's abstract flows, so
client authentication, metadata lookup, intercepts, auditing, and metrics work as they do in the OP.

The plugin provides three endpoints:

| Endpoint | Description |
|---|---|
| `/idp/profile/oauth2/devicegrant/authorize` | Device authorization endpoint, RFC 8628 section 3.1. |
| `/idp/profile/oauth2/devicegrant/authenticate` | Verification URI, the user enters the user code and approves. |
| `/idp/profile/oauth2/devicegrant/token` | Token endpoint (RFC 8628, Section 3.4). It also supports the grant types supported by the OP token endpoint. |

Key points:

- The plugin supports only OIDC OP 4.3; see [Plugin Installation](#plugin-installation).
- Its token endpoint is based on the OP 4.3.0 token endpoint, with the device code grant added.

## Plugin Installation

> **Note**
> Install this plugin only with OIDC OP **4.3** (version 4.3.0 or a patch release). The plugin
> includes a copy of the OP 4.3.0 token endpoint and uses classes and beans from that release.
> Other OP versions are not supported. The plugin has been tested with OP 4.3.1.

| Plugin | Plugin ID | Module(s) | Depends on | Bug Reporting |
|---|---|---|---|---|
| OAuth 2.0 Device Authorization Grant | `fi.csc.shibboleth.plugin.oauth2.devicegrant` | `idp.DeviceGrant` | `idp.oidc.OP.6` | janne.lauros@csc.fi |

Requires IdP **5.0.0** or later and OIDC OP **4.3**.

### Dependencies

> **Note**
> This plugin depends on the OpenID Connect OP plugin and its dependencies. Install them **first**,
> following the Shibboleth wiki's [OIDC OP installation instructions](https://shibboleth.atlassian.net/wiki/spaces/IDPPLUGINS/pages/1376878976/OIDC+OP).

### Installation example

Download releases from this repository's [releases page](https://github.com/CSCfi/shibboleth-idp-oauth2-deviceflow-extension/releases).

The release-signing key is in
[keys.txt](oauth2-devicegrant-dist/src/main/resources/bootstrap/keys.txt). The plugin uses this key
as its truststore.

<details>
<summary>Example installation of this plugin</summary>

```bash
cd /opt/shibboleth-idp

# The distribution-signing key becomes the plugin's truststore.
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

Installing the plugin activates the `idp.DeviceGrant` module and creates four files:

| File | Description |
|---|---|
| *conf/devicegrant.properties* | Every deployer-facing property. |
| *views/oauth2/devicegrant/authenticate-usercode.vm* | The page where the user enters the user code. |
| *views/oauth2/devicegrant/authenticate-userapproval.vm* | The page where the user approves or denies the device. |
| *views/oauth2/devicegrant/authenticate-end.vm* | The page shown after the decision. |

## First installation, by example

Step 1 configures the device grant for a confidential client and demonstrates the flow with curl.
Step 2 adds a requested authentication method. Step 3 configures the verification URI shown to the user.
Step 4 makes the plugin's token endpoint the OP's only token endpoint.
The examples come from one test deployment and are designed to work together, but may need changes
for your environment.

In the examples below, `https://idp.example.org` is the IdP's base URL.

### Step 1: A confidential client

#### Relying party

**File(s):** *conf/relying-party.xml*
**Format:** Native Spring

Enable the device authorization and user verification endpoints with **OAUTH2.DeviceGrant**.
Configure the token endpoint with the OP's **OAUTH2.Token**, adding the device code grant to
`grantTypes`. Because device clients are registered clients, both configurations belong in the
default relying party:

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

Instead of setting `p:grantTypes` here, you can add the grant type for all relying parties by setting
the OP property `idp.oauth2.grantTypes` in *conf/oidc.properties*.

#### Client registration

**File(s):** *metadata/oidc-client.json*
**Format:** JSON

Register the device as an OIDC client of the OP. Add the device grant to `grant_types` and list
the scopes the client may request in `scope`:

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

The device requests a device code and a user code:

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

The OP checks the requested scopes against the client's `scope` value. Scopes the client is not
allowed to request are omitted. If the OP uses strict scope validation, the request fails with
`invalid_scope`.

#### User verification

The user opens `verification_uri` and enters the user code, or opens `verification_uri_complete`,
which already includes the code. Letter case does not matter, and spaces and dashes are ignored.
The user then authenticates and approves or denies the request. Each user code can be used only once.

#### Token request

The device polls the token endpoint with the device code, no more frequently than once every
`interval` seconds:

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

If the device polls more frequently than `interval`, the endpoint returns `slow_down`. The device
must then increase the polling interval by 5 seconds, as specified in RFC 8628, Section 3.5. Each
subsequent request that arrives too early adds another 5 seconds.

A device code can be used to obtain only one token response. A second request with the same code
returns `invalid_grant`; the same error is returned if a different client uses the code. If the user
denies the request, the endpoint returns `access_denied`. If the device code has expired, it returns
`expired_token`.

If the device authorization request includes `scope=openid`, the response also contains an `id_token`.

### Step 2: Requesting an authentication method

**File(s):** *conf/authn/authn.properties*
**Format:** Java properties

The device can request an authentication method by setting `acr_values`. An authentication flow
must support a principal with the requested value. The plugin always treats requested values as
essential. This example enables the Password flow and configures it to support
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

The device displays the verification URI to the user. The authorization response includes it as
`verification_uri` and includes the URI with the user code appended as `verification_uri_complete`.
If you do not configure the URI, the plugin builds it from the host, port, and context path of the
device authorization request. For example:
`https://idp.example.org/idp/profile/oauth2/devicegrant/authenticate`.

#### A short verification URI

**File(s):** *conf/devicegrant.properties*, *etc/jetty-rewrite-rules.xml* of the Jetty base
**Format:** Java properties, Jetty XML

Users may need to type the verification URI shown on the device screen, so a short URI is easier
to use. Configure it as follows:

<details>
<summary>conf/devicegrant.properties</summary>

```properties
devicegrant.verificationURI = https://idp.example.org/shortExample
```

Full file: [conf/devicegrant.properties](docs/example/step-3/conf/devicegrant.properties)

</details>

Configure Jetty to redirect this URI to the user verification endpoint and preserve the query
string, which contains the user code from `verification_uri_complete`. Enable Jetty's `rewrite`
module and add this rule:

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

The device authorization response now contains the short URI:

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

`verificationURI` is a setting of **OAUTH2.DeviceGrant**. To set it for a single client, use a
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

Use this setup only if device clients must use the plugin's token endpoint while other clients
continue to use the OP's token endpoint.

The plugin's token endpoint also supports the grant types handled by the OP token endpoint:
`authorization_code`, `refresh_token`, `client_credentials`, and the device code grant. All use
**OAUTH2.Token**, so one endpoint can serve all clients. The plugin does not publish this endpoint
automatically. Choose one of the following options to make clients use it:

- [Option 1: Publishing the token endpoint of the plugin](#option-1-publishing-the-token-endpoint-of-the-plugin):
  The discovery document advertises the plugin's token endpoint. Clients that use the discovery
  document will then use this endpoint.
- [Option 2: Rewriting the OP token endpoint](#option-2-rewriting-the-op-token-endpoint): the
  The discovery document continues to advertise the OP token endpoint, while Jetty rewrites requests
  to the plugin's token endpoint. This also works for clients configured to use the OP token endpoint.

#### Option 1: Publishing the token endpoint of the plugin

**File(s):** *static/openid-configuration.json*
**Format:** JSON

Set the plugin's token endpoint as the discovery document's `token_endpoint` value:

```json
"token_endpoint": "https://idp.example.org/idp/profile/oauth2/devicegrant/token",
```

The OP token endpoint at `/idp/profile/oidc/token` remains available to clients that have its URL
configured directly.

#### Option 2: Rewriting the OP token endpoint

**File(s):** *etc/jetty-rewrite-rules.xml* of the Jetty base, *conf/oidc.properties*
**Format:** Jetty XML, Java properties

If `token_endpoint` must remain `https://idp.example.org/idp/profile/oidc/token`, configure Jetty
to rewrite requests to the plugin's token endpoint. Enable Jetty's `rewrite` module and add this rule:

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

After rewriting, the IdP receives the request at the plugin's endpoint, but the client signs the
URL it originally called:

- **DPoP.** The `htu` claim in a DPoP proof contains the URL called by the client. Set the plugin's
  DPoP proof claims validator to **OAUTH2.Token** so it accepts the OP token endpoint URL as `htu`
  when the request reaches the plugin's token endpoint. The property
  `devicegrant.token.endpointReplacement` sets the OP token endpoint path; the default is
  `/profile/oidc/token`. A relying party override with its own **OAUTH2.Token**, as shown in
  [One client only](#one-client-only), also needs this validator.
- **JWT client authentication.** The `aud` claim in a `client_secret_jwt` or `private_key_jwt`
  assertion can be the issuer or the token endpoint URL. The issuer is always accepted. To accept
  the OP token endpoint URL, add the plugin's token endpoint to the OP endpoints that accept that URL:

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

This profile configures the endpoints `/idp/profile/oauth2/devicegrant/authorize` and
`/idp/profile/oauth2/devicegrant/authenticate`. Its profile ID is
`http://csc.fi/ns/profiles/oauth.net/2/device-flow`.

This bean extends **AbstractOIDCSSOProfile** from the OIDC Config plugin, so that bean's settings
also apply. **OAUTH2.DeviceGrant.MDDriven** is the metadata-driven variant.

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

The endpoint `/idp/profile/oauth2/devicegrant/token` uses **OAUTH2.Token** from the OIDC Config
plugin and has the same settings as the OP token endpoint. Add
`urn:ietf:params:oauth:grant-type:device_code` to `grantTypes`.

The plugin provides the **devicegrant.DPoPProofClaimsValidator** bean for the
`dpopProofClaimsValidator` setting. It uses the OP's DPoP proof claims validators and also accepts
the OP token endpoint URL as `htu`. See
[Option 2: Rewriting the OP token endpoint](#option-2-rewriting-the-op-token-endpoint).

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

Define these beans to override the defaults.

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

The views use the message keys `idp.login.usercode*`, `idp.login.device.*`, and `idp.device.*`.
English text is provided by default. Add translations in *messages/messages.properties*.
