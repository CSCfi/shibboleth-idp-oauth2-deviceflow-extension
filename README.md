[![CodeQL](https://github.com/CSCfi/shibboleth-idp-oauth2-deviceflow-extension/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/CSCfi/shibboleth-idp-oauth2-deviceflow-extension/actions/workflows/codeql-analysis.yml)

# shibboleth-idp-oauth2-deviceflow-extension
OAuth2 Device Flow extension for shibboleth-idp-oidc-extension. See https://tools.ietf.org/html/rfc8628.

## Prerequisite for installation
- Shibboleth IdP 4.0.0+ 
- [shibboleth-idp-oidc-extension](https://github.com/CSCfi/shibboleth-idp-oidc-extension/wiki) v2.0.0+

## Installation
First you need extract the archive and rebuild the package. Please not that you most likely *need* to change the owner and group information of the extracted files to suite your installation.

    cd /opt/shibboleth-idp
    tar -xf path/to/idp-oauth2-deviceflow-extension-distribution-2.X.X-bin.tar.gz --strip-components=1
    bin/build.sh

Next you need to import oauth2-deviceflow-relying-party.xml to oidc-relying-party.xml.

    edit /opt/shibboleth-idp/conf/oidc-relying-party.xml

Add following line:

    <import resource="oauth2-deviceflow-relying-party.xml"/>
    
While editing the file add the new profile also to profileResponders map.

    <!-- Configure profiles that need to use issuer instead of entity id as responder id. -->
    <util:map id="profileResponders">
        <entry key-ref="OIDC.SSO" value="#{getObject('issuer')}" />
        <entry key-ref="OIDC.Registration" value="#{getObject('issuer')}" />
        <entry key-ref="OIDC.Configuration" value="#{getObject('issuer')}" />
        <entry key-ref="OAUTH2.Device" value="#{getObject('issuer')}" />
    </util:map>

Then you need to list the new [idp-oauth2-deviceflow.properties](https://github.com/CSCfi/shibboleth-idp-oauth2-deviceflow-extension/blob/master/idp-oauth2-deviceflow-extension-distribution/src/main/resources/conf/idp-oauth2-deviceflow.properties) properties file in the main properties file.

    edit /opt/shibboleth-idp/conf/idp.properties

    idp.additionalProperties=/conf/ldap.properties, /conf/saml-nameid.properties, /conf/services.properties,/conf/authn/duo.properties, /conf/oidc-subject.properties, /conf/idp-oidc.properties, /conf/idp-oauth2-deviceflow.properties
    
Now we need to activate still the profile configuration by adding [OAUTH2.Device](https://github.com/CSCfi/shibboleth-idp-oauth2-deviceflow-extension/wiki/ProfileConfiguration) to relying-party.xml

    edit /opt/shibboleth-idp/conf/relying-party.xml
    
    <bean id="shibboleth.DefaultRelyingParty" p:responderIdLookupStrategy-ref="profileResponderIdLookupFunction"   parent="RelyingParty">
    <property name="profileConfigurations">
        <list>
            <bean parent="Shibboleth.SSO" p:postAuthenticationFlows="attribute-release" />
            <ref bean="SAML1.AttributeQuery" />
            <ref bean="SAML1.ArtifactResolution" />
            <bean parent="SAML2.SSO" p:postAuthenticationFlows="attribute-release" />
            <ref bean="SAML2.ECP" />
            <ref bean="SAML2.Logout" />
            <ref bean="SAML2.AttributeQuery" />
            <ref bean="SAML2.ArtifactResolution" />
            <ref bean="Liberty.SSOS" />
            <bean parent="OIDC.SSO" p:postAuthenticationFlows="attribute-release" />
            <bean parent="OIDC.UserInfo"/>
            <bean parent="OAUTH2.Revocation"/>
            <bean parent="OAUTH2.Device"/>
        </list>
    </property>
    </bean>

## Configuring OP for the Device Flow client
The client must have have urn:ietf:params:oauth:grant-type:device_code grant type listed in the metadata.

    [
      {
        "scope":"device",
        "client_id":"test_rp",
        "client_secret":"testSecret1234",
        "grant_types":["urn:ietf:params:oauth:grant-type:device_code"]
      }
    ]
 For implementation limitations it is mandatory to list atleast one scope in client's metadata even if the scope was not applied. 

Make sure your attribute filter is such that sub claim is resolved also for the Device Flow client. 

## Configuring Client for the Device Flow

* Authorization Endpoint: idp/profile/oauth2/device/authorize
* Token Endpoint: idp/profile/oauth2/device/token
* UserInfo Endpoint: Standard endpoint of your installation


    
