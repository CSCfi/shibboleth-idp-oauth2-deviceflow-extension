/*
 * Copyright (c) 2019-2020 CSC- IT Center for Science, www.csc.fi
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fi.csc.idpextension.oauth2.profile.impl;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

import fi.csc.idpextension.oauth2.config.OAuth2DeviceFlowConfiguration;
import fi.csc.idpextension.oauth2.profile.context.navigate.DeviceUserApprovalLookupFunction;
import fi.csc.idpextension.oauth2.profile.context.navigate.DeviceUserCodeLookupFunction;
import fi.csc.idpextension.storage.DeviceCodeObject;
import fi.csc.idpextension.storage.DeviceCodesCache;
import fi.csc.idpextension.storage.DeviceStateObject;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.ParseException;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.ResponderIdLookupFunction;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseConsentContext;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.geant.idpextension.oidc.profile.context.navigate.OIDCAuthenticationResponseContextLookupFunction;
import org.geant.idpextension.oidc.profile.impl.AbstractOIDCResponseAction;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;

import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.DataSealerException;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.security.impl.SecureRandomIdentifierGenerationStrategy;

/**
 * Action storing user approval action, approved or denied to {@link DeviceCodesCache} as a {@link DeviceStateObject}.
 * In the case user approved the request the {@link DeviceStateObject} contains a access token that may be queried by a
 * trusted rp using Device Code.
 */
public class StoreDeviceState extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(StoreDeviceState.class);

    /** Expiration of device/user codes in milliseconds. */
    private Duration expiration;

    /** Device code matching the user code. */
    @Nullable
    String deviceCode;

    /** Cache for DeviceCodeObjects and DeviceStateObjects. */
    @NonnullAfterInit
    private DeviceCodesCache deviceCodesCache;

    /** Access Token lifetime. */
    private Duration accessTokenLifetime;

    /** Data sealer for handling access token. */
    @Nonnull
    private final DataSealer dataSealer;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Relying party information. */
    @Nullable
    RelyingPartyContext rpCtx;

    /** Strategy used to obtain the response issuer value. */
    @Nonnull
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /** Subject context. */
    private SubjectContext subjectCtx;

    /** The generator to use. */
    @Nullable
    private IdentifierGenerationStrategy idGenerator;

    /** Strategy used to locate the {@link IdentifierGenerationStrategy} to use. */
    @Nonnull
    private Function<ProfileRequestContext, IdentifierGenerationStrategy> idGeneratorLookupStrategy;

    /**
     * Strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> tokenClaimsContextLookupStrategy;

    /**
     * Strategy used to locate the {@link OIDCAuthenticationResponseConsentContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseConsentContext> consentContextLookupStrategy;

    /** Strategy to locate user code. */
    @Nonnull
    private Function<MessageContext, String> userCodeLookupStrategy;

    /** Strategy to locate user approval. */
    @Nonnull
    private Function<MessageContext, Boolean> userApprovalLookupStrategy;

    /**
     * Constructor.
     * 
     * @param sealer sealer to encrypt/hmac access token.
     */
    public StoreDeviceState(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        userCodeLookupStrategy = new DeviceUserCodeLookupFunction();
        userApprovalLookupStrategy = new DeviceUserApprovalLookupFunction();

        tokenClaimsContextLookupStrategy = new ChildContextLookup<>(OIDCAuthenticationResponseTokenClaimsContext.class)
                .compose(new OIDCAuthenticationResponseContextLookupFunction());
        consentContextLookupStrategy = new ChildContextLookup<>(OIDCAuthenticationResponseConsentContext.class)
                .compose(new OIDCAuthenticationResponseContextLookupFunction());
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
        issuerLookupStrategy = (Function<ProfileRequestContext, String>) new ResponderIdLookupFunction();
        idGeneratorLookupStrategy = new Function<ProfileRequestContext, IdentifierGenerationStrategy>() {
            public IdentifierGenerationStrategy apply(ProfileRequestContext input) {
                return new SecureRandomIdentifierGenerationStrategy();
            }
        };
    }

    /**
     * Set strategy to locate user code.
     * 
     * @param strategy Strategy to locate user code
     */
    public void setDeviceUserCodeLookupStrategy(@Nonnull final Function<MessageContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        userCodeLookupStrategy =
                Constraint.isNotNull(strategy, "DeviceUserCodeLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set strategy to locate user approval.
     * 
     * @param strategy Strategy to locate user approval
     */
    public void setDeviceUserApprovalLookupStrategy(@Nonnull final Function<MessageContext, Boolean> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        userApprovalLookupStrategy =
                Constraint.isNotNull(strategy, "DeviceUserApprovalLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the device code cache instance to use.
     * 
     * @param cache The device code cache to set.
     */
    public void setDeviceCodesCache(@Nonnull final DeviceCodesCache cache) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        deviceCodesCache = Constraint.isNotNull(cache, "DeviceCodesCache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        Constraint.isNotNull(deviceCodesCache, "DeviceCodesCache cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setOIDCAuthenticationResponseTokenClaimsContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        tokenClaimsContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCAuthenticationResponseTokenClaimsContextt lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setOIDCAuthenticationResponseConsentContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseConsentContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        consentContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCAuthenticationResponseConsentContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link RelyingPartyContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy strategy used to locate the {@link RelyingPartyContext} associated with a given
     *            {@link ProfileRequestContext}
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        relyingPartyContextLookupStrategy =
                Constraint.isNotNull(strategy, "RelyingPartyContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link IdentifierGenerationStrategy} to use.
     * 
     * @param strategy lookup strategy
     */
    public void setIdentifierGeneratorLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, IdentifierGenerationStrategy> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        idGeneratorLookupStrategy =
                Constraint.isNotNull(strategy, "IdentifierGenerationStrategy lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the issuer value to use.
     * 
     * @param strategy lookup strategy
     */
    public void setIssuerLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        issuerLookupStrategy = Constraint.isNotNull(strategy, "IssuerLookupStrategy lookup strategy cannot be null");
    }

    // Checkstyle: CyclomaticComplexity OFF
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        String userCode = userCodeLookupStrategy.apply(profileRequestContext.getInboundMessageContext());
        if (userCode == null || userCode.isEmpty()) {
            log.error("{} No user code", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return false;
        }
        try {
            DeviceCodeObject deviceCodeObject = deviceCodesCache.getDeviceCode(userCode);
            if (deviceCodeObject == null || deviceCodeObject.getDeviceCode() == null) {
                log.error("{} No device code for user code", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return false;
            }
            deviceCode = deviceCodeObject.getDeviceCode();
        } catch (IOException | ParseException e) {
            log.error("{} Error accessing device code cache", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return false;
        }
        rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null) {
            log.error("{} No relying party context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        final ProfileConfiguration pc = rpCtx.getProfileConfig();
        if (pc != null && pc instanceof OAuth2DeviceFlowConfiguration) {
            accessTokenLifetime = ((OAuth2DeviceFlowConfiguration) pc).getAccessTokenLifetime(profileRequestContext);
            expiration = ((OAuth2DeviceFlowConfiguration) pc).getDeviceCodeLifetime(profileRequestContext);
        } else {
            log.error("{} No oidc profile configuration associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        subjectCtx = profileRequestContext.getSubcontext(SubjectContext.class, false);
        if (subjectCtx == null) {
            log.error("{} No subject context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        idGenerator = idGeneratorLookupStrategy.apply(profileRequestContext);
        if (idGenerator == null) {
            log.error("{} No identifier generation strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return true;
    }
    // Checkstyle: CyclomaticComplexity ON

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        DeviceStateObject deviceStateObject = null;
        if (!userApprovalLookupStrategy.apply(profileRequestContext.getInboundMessageContext())) {
            deviceStateObject = new DeviceStateObject(DeviceStateObject.State.DENIED);
        } else {
            Instant dateExp = Instant.now().plusMillis(accessTokenLifetime.toMillis());
            ClaimsSet claims = null;
            ClaimsSet claimsUI = null;
            OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx =
                    tokenClaimsContextLookupStrategy.apply(profileRequestContext);
            if (tokenClaimsCtx != null) {
                claims = tokenClaimsCtx.getClaims();
                claimsUI = tokenClaimsCtx.getUserinfoClaims();
            }
            AccessTokenClaimsSet claimsSet;
            JSONArray consentable = null;
            JSONArray consented = null;
            OIDCAuthenticationResponseConsentContext consentCtx =
                    consentContextLookupStrategy.apply(profileRequestContext);
            if (consentCtx != null) {
                consentable = consentCtx.getConsentableAttributes();
                consented = consentCtx.getConsentedAttributes();
            }
            try {
                claimsSet = new AccessTokenClaimsSet.Builder(idGenerator, new ClientID(rpCtx.getRelyingPartyId()),
                        issuerLookupStrategy.apply(profileRequestContext), subjectCtx.getPrincipalName(),
                        getOidcResponseContext().getSubject(), Instant.now(), dateExp,
                        /** redirect_uri is not relevant in device flow as we do not redirect user. */
                        getOidcResponseContext().getAuthTime(), new URI("https://example.com"),
                        getOidcResponseContext().getScope()).setACR(getOidcResponseContext().getAcr())
                                .setConsentableClaims(consentable).setConsentedClaims(consented).setDlClaims(claims)
                                .setDlClaimsUI(claimsUI).build();
                deviceStateObject = new DeviceStateObject(DeviceStateObject.State.APPROVED,
                        claimsSet.serialize(dataSealer), System.currentTimeMillis() + accessTokenLifetime.toMillis());
                log.debug("{} Generated access token {} as {} expiring at {}", getLogPrefix(), claimsSet.serialize(),
                        deviceStateObject.getAccessToken(), deviceStateObject.getExpiresAt());
            } catch (DataSealerException | URISyntaxException e) {
                log.error("{} Access Token generation failed {}", getLogPrefix(), e);
                ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
                return;
            }
        }
        try {
            if (!deviceCodesCache.updateDeviceState(deviceCode, deviceStateObject, expiration.toMillis())) {
                log.error("{} Unable to update device state object to approved ", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
                return;
            }
            log.debug("{} Device {} state updated as {}", getLogPrefix(), deviceCode,
                    deviceStateObject.getState().toString());
        } catch (IOException | ParseException e) {
            log.error("{} Access Token generation failed {}", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
        }
    }
}