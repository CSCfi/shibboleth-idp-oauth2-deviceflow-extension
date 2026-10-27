/*
 * Copyright (c) 2019-2024 CSC- IT Center for Science, www.csc.fi
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

package fi.csc.shibboleth.plugin.oauth2.profile.impl;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;
import java.util.function.Predicate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

import fi.csc.shibboleth.plugin.oauth2.config.OAuth2DeviceGrantConfiguration;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.DeviceEventIds;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.context.navigate.DeviceUserApprovalLookupFunction;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.context.navigate.DeviceUserCodeLookupFunction;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodeObject;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodesCache;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceStateObject;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.ParseException;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.plugin.oidc.op.messaging.context.OIDCAuthenticationResponseConsentContext;
import net.shibboleth.idp.plugin.oidc.op.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import net.shibboleth.idp.plugin.oidc.op.profile.context.navigate.OIDCAuthenticationResponseContextLookupFunction;
import net.shibboleth.idp.plugin.oidc.op.profile.impl.AbstractOIDCResponseAction;
import net.shibboleth.idp.plugin.oidc.op.token.support.AuthorizeCodeClaimsSet;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.oidc.profile.config.logic.AttributeConsentFlowEnabledPredicate;
import net.shibboleth.profile.config.ProfileConfiguration;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.profile.context.navigate.IssuerLookupFunction;
import net.shibboleth.shared.annotation.ParameterName;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.security.DataSealer;
import net.shibboleth.shared.security.DataSealerException;
import net.shibboleth.shared.security.IdentifierGenerationStrategy;
import net.shibboleth.shared.security.impl.SecureRandomIdentifierGenerationStrategy;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;

/**
 * Action storing the user decision to {@link DeviceCodesCache} as a {@link DeviceStateObject}.
 */
public class StoreDeviceState extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(StoreDeviceState.class);

    /** Expiration of device/user codes in milliseconds. */
    private Duration expiration;

    /** Device code matching the user code. */
    @Nullable
    private String deviceCode;

    /** User code. */
    @Nullable
    private String userCode;

    /** Cache for DeviceCodeObjects and DeviceStateObjects. */
    @NonnullAfterInit
    private DeviceCodesCache deviceCodesCache;

    /** Data sealer for the grant claims set. */
    @Nonnull
    private final DataSealer dataSealer;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a
     * given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Relying party information. */
    @Nullable
    private RelyingPartyContext rpCtx;

    /** Strategy used to obtain the response issuer value. */
    @Nonnull
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /**
     * Predicate used to check if consent is enabled with a given
     * {@link ProfileRequestContext}.
     */
    @Nonnull
    private Predicate<ProfileRequestContext> consentEnabledPredicate;

    /** Subject context. */
    private SubjectContext subjectCtx;

    /** The generator to use. */
    @Nullable
    private IdentifierGenerationStrategy idGenerator;

    /** Strategy used to locate the {@link IdentifierGenerationStrategy} to use. */
    @Nonnull
    private Function<ProfileRequestContext, IdentifierGenerationStrategy> idGeneratorLookupStrategy;

    /**
     * Strategy used to locate the
     * {@link OIDCAuthenticationResponseTokenClaimsContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext>
            tokenClaimsContextLookupStrategy;

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
     * @param sealer sealer to encrypt/hmac the grant claims set.
     */
    public StoreDeviceState(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        userCodeLookupStrategy = new DeviceUserCodeLookupFunction();
        userApprovalLookupStrategy = new DeviceUserApprovalLookupFunction();

        tokenClaimsContextLookupStrategy = new ChildContextLookup<>(OIDCAuthenticationResponseTokenClaimsContext.class)
                .compose(new OIDCAuthenticationResponseContextLookupFunction());
        consentContextLookupStrategy = new ChildContextLookup<>(OIDCAuthenticationResponseConsentContext.class)
                .compose(new OIDCAuthenticationResponseContextLookupFunction());
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
        consentEnabledPredicate = new AttributeConsentFlowEnabledPredicate();
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
        issuerLookupStrategy = (Function<ProfileRequestContext, String>) new IssuerLookupFunction();
        idGeneratorLookupStrategy = new Function<ProfileRequestContext, IdentifierGenerationStrategy>() {
            public IdentifierGenerationStrategy apply(final ProfileRequestContext input) {
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
        checkSetterPreconditions();
        userCodeLookupStrategy = Constraint.isNotNull(strategy,
                "DeviceUserCodeLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set strategy to locate user approval.
     * 
     * @param strategy Strategy to locate user approval
     */
    public void setDeviceUserApprovalLookupStrategy(@Nonnull final Function<MessageContext, Boolean> strategy) {
        checkSetterPreconditions();
        userApprovalLookupStrategy = Constraint.isNotNull(strategy,
                "DeviceUserApprovalLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the device code cache instance to use.
     * 
     * @param cache The device code cache to set.
     */
    public void setDeviceCodesCache(@Nonnull final DeviceCodesCache cache) {
        checkSetterPreconditions();
        deviceCodesCache = Constraint.isNotNull(cache, "DeviceCodesCache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        Constraint.isNotNull(deviceCodesCache, "DeviceCodesCache cannot be null");
    }

    /**
     * Set the strategy used to locate the
     * {@link OIDCAuthenticationResponseTokenClaimsContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setOIDCAuthenticationResponseTokenClaimsContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> strategy) {
        checkSetterPreconditions();
        tokenClaimsContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCAuthenticationResponseTokenClaimsContextt lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the
     * {@link OIDCAuthenticationResponseTokenClaimsContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setOIDCAuthenticationResponseConsentContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseConsentContext> strategy) {
        checkSetterPreconditions();
        consentContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCAuthenticationResponseConsentContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link RelyingPartyContext} associated
     * with a given {@link ProfileRequestContext}.
     * 
     * @param strategy strategy used to locate the {@link RelyingPartyContext}
     *                 associated with a given {@link ProfileRequestContext}
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        checkSetterPreconditions();

        relyingPartyContextLookupStrategy = Constraint.isNotNull(strategy,
                "RelyingPartyContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link IdentifierGenerationStrategy} to
     * use.
     * 
     * @param strategy lookup strategy
     */
    public void setIdentifierGeneratorLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, IdentifierGenerationStrategy> strategy) {
        checkSetterPreconditions();

        idGeneratorLookupStrategy = Constraint.isNotNull(strategy,
                "IdentifierGenerationStrategy lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the issuer value to use.
     * 
     * @param strategy lookup strategy
     */
    public void setIssuerLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        checkSetterPreconditions();
        issuerLookupStrategy = Constraint.isNotNull(strategy, "IssuerLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the predicate used to check if consent is enabled with a given
     * {@link ProfileRequestContext}.
     * 
     * @param predicate predicate used to check if consent is enabled with a given
     *                  {@link ProfileRequestContext}.
     */
    public void setConsentEnabledPredicate(@Nonnull final Predicate<ProfileRequestContext> predicate) {
        checkSetterPreconditions();
        consentEnabledPredicate = Constraint.isNotNull(predicate,
                "predicate used to check if consent is enabled cannot be null");
    }

    // Checkstyle: CyclomaticComplexity|ReturnCount OFF
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        userCode = userCodeLookupStrategy.apply(profileRequestContext.getInboundMessageContext());
        if (userCode == null || userCode.isEmpty()) {
            log.error("{} No user code", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return false;
        }
        try {
            final DeviceCodeObject deviceCodeObject = deviceCodesCache.getDeviceCode(userCode);
            if (deviceCodeObject == null || deviceCodeObject.getDeviceCode() == null) {
                log.error("{} No device code for user code", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return false;
            }
            deviceCode = deviceCodeObject.getDeviceCode();
        } catch (final IOException | ParseException e) {
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
        if (pc != null && pc instanceof OAuth2DeviceGrantConfiguration) {
            expiration = ((OAuth2DeviceGrantConfiguration) pc).getDeviceCodeLifetime(profileRequestContext);
        } else {
            log.error("{} No oidc profile configuration associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        subjectCtx = profileRequestContext.getSubcontext(SubjectContext.class);
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
    // Checkstyle: CyclomaticComplexity|ReturnCount ON

    // Checkstyle: CyclomaticComplexity|MethodLength OFF
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        try {
            if (!deviceCodesCache.removeDeviceCode(userCode)) {
                log.error("{} User code has already been used", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.INVALID_USER_CODE);
                return;
            }
        } catch (final IOException e) {
            log.error("{} Error accessing device code cache", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return;
        }
        final DeviceStateObject currentStateObject;
        try {
            currentStateObject = deviceCodesCache.getDeviceState(deviceCode);
        } catch (final IOException | ParseException e) {
            log.error("{} Error accessing device code cache", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return;
        }
        if (currentStateObject == null) {
            log.error("{} No device state for the device code", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        DeviceStateObject deviceStateObject = null;
        if (!userApprovalLookupStrategy.apply(profileRequestContext.getInboundMessageContext())) {
            deviceStateObject = currentStateObject.withState(DeviceStateObject.State.DENIED, null, null);
        } else {
            final Instant now = Instant.now();
            final Instant dateExp = now.plus(expiration);
            ClaimsSet claims = null;
            ClaimsSet claimsUI = null;
            final OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx = tokenClaimsContextLookupStrategy
                    .apply(profileRequestContext);
            if (tokenClaimsCtx != null) {
                claims = tokenClaimsCtx.getClaims();
                claimsUI = tokenClaimsCtx.getUserinfoClaims();
            }
            final AuthorizeCodeClaimsSet claimsSet;
            JSONArray consented = null;
            final OIDCAuthenticationResponseConsentContext consentCtx = consentContextLookupStrategy
                    .apply(profileRequestContext);
            if (consentCtx != null) {
                consented = consentCtx.getConsentedAttributes();
            }
            try {
                claimsSet = new AuthorizeCodeClaimsSet.Builder().setJWTID(idGenerator)
                        .setClientID(new ClientID(rpCtx.getRelyingPartyId()))
                        .setIssuer(issuerLookupStrategy.apply(profileRequestContext))
                        .setPrincipal(subjectCtx.getPrincipalName()).setSubject(getOidcResponseContext().getSubject())
                        .setIssuedAt(now).setExpiresAt(dateExp).setACR(getOidcResponseContext().getAcr())
                        .setAuthenticationTime(getOidcResponseContext().getAuthTime())
                        .setScope(getOidcResponseContext().getScope()).setConsentedClaims(consented).setDlClaims(claims)
                        .setDlClaimsUI(claimsUI).setConsentEnabled(consentEnabledPredicate.test(profileRequestContext))
                        .setSessionIdentifier(getOidcResponseContext().getSessionId())
                        .build();
                deviceStateObject = currentStateObject.withState(DeviceStateObject.State.APPROVED,
                        claimsSet.serialize(dataSealer), dateExp.toEpochMilli());
                log.debug("{} Generated grant claims set {} expiring at {}", getLogPrefix(), claimsSet.serialize(),
                        dateExp);
            } catch (final DataSealerException e) {
                log.error("{} Grant claims set generation failed", getLogPrefix(), e);
                ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
                return;
            }
        }
        try {
            if (!deviceCodesCache.updateDeviceState(deviceCode, deviceStateObject)) {
                log.error("{} Unable to update device state object to approved ", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
                return;
            }
            log.debug("{} Device state updated as {}", getLogPrefix(), deviceStateObject.getState().toString());
        } catch (final IOException e) {
            log.error("{} Error storing device state", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
        }
    }
    // Checkstyle: CyclomaticComplexity|MethodLength ON
}