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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.id.ClientID;

import fi.csc.shibboleth.plugin.oauth2.config.OAuth2DeviceGrantConfiguration;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodeObject;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodesCache;
import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthorizationRequest;
import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthorizationSuccessResponse;
import net.shibboleth.idp.plugin.oidc.op.profile.impl.AbstractOIDCResponseAction;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.profile.config.ProfileConfiguration;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.logic.FunctionSupport;
import net.shibboleth.shared.security.IdentifierGenerationStrategy;
import net.shibboleth.shared.security.IdentifierGenerationStrategy.ProviderType;
import net.shibboleth.shared.security.RandomIdentifierParameterSpec;
import net.shibboleth.shared.servlet.HttpServletSupport;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Action forming device authorization response success message. Action
 * generates user and device codes, forms a {@link DeviceCodeObject} storing it
 * to {@link DeviceCodesCache} keyed with user code. Finally the action forms
 * {@link OAuth2DeviceAuthorizationSuccessResponse}
 */
public class FormOutboundDeviceAuthorizationResponseMessage extends AbstractOIDCResponseAction {

    /** Random bytes of the default device code generator. */
    public static final int DEVICE_CODE_RANDOM_BYTES = 32;

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(FormOutboundDeviceAuthorizationResponseMessage.class);

    /** Cache for device codes. */
    @NonnullAfterInit
    private DeviceCodesCache deviceCodesCache;

    /** Strategy used to locate the {@link IdentifierGenerationStrategy} to use. */
    @NonnullAfterInit
    private Function<ProfileRequestContext, IdentifierGenerationStrategy> idGeneratorLookupStrategy;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a
     * given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Length of the device code. */
    private long deviceCodeLength;

    /** Length of the user code. */
    private long userCodeLength;

    /** Expiration of device/user codes in milliseconds. */
    private Duration expiration;

    /** Relying party context. */
    private RelyingPartyContext rpCtx;

    /** Authentication endpoint not including server name and protocol. */
    private String authenticationEndpoint = "/profile/oauth2/devicegrant/authenticate";

    /** Verification URI. */
    @Nullable
    private String verificationURI;

    /** Interval between polling requests. */
    private Duration interval;

    /**
     * Inbound request. Nonnull after pre-execute.
     */
    @NonnullAfterInit
    private OAuth2DeviceAuthorizationRequest request;

    /**
     * Constructor.
     */
    public FormOutboundDeviceAuthorizationResponseMessage() {
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
    }

    /**
     * Set authentication endpoint not including server name and protocol.
     * 
     * @param endpoint authentication endpoint not including server name and
     *                 protocol
     */
    public void setAuthenticationEndpoint(final String endpoint) {
        authenticationEndpoint = endpoint;
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
     * Set the device code cache instance to use.
     * 
     * @param cache The device code to set.
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
        if (idGeneratorLookupStrategy == null) {
            try {
                idGeneratorLookupStrategy = FunctionSupport.constant(IdentifierGenerationStrategy.getInstance(
                        ProviderType.SECURE, new RandomIdentifierParameterSpec(null, DEVICE_CODE_RANDOM_BYTES, null)));
            } catch (final InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
                throw new ComponentInitializationException(e);
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (getHttpServletRequest() == null) {
            log.error("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        if (idGeneratorLookupStrategy.apply(profileRequestContext) == null) {
            log.error("{} No identifier generation strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null) {
            log.error("{} No relying party context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        final ProfileConfiguration pc = rpCtx.getProfileConfig();
        if (pc instanceof OAuth2DeviceGrantConfiguration) {
            deviceCodeLength = ((OAuth2DeviceGrantConfiguration) pc).getDeviceCodeLength(profileRequestContext);
            userCodeLength = ((OAuth2DeviceGrantConfiguration) pc).getUserCodeLength(profileRequestContext);
            expiration = ((OAuth2DeviceGrantConfiguration) pc).getDeviceCodeLifetime(profileRequestContext);
            interval = ((OAuth2DeviceGrantConfiguration) pc).getPollingInterval(profileRequestContext);
            verificationURI = ((OAuth2DeviceGrantConfiguration) pc).getVerificationURI(profileRequestContext);
        } else {
            log.error("{} No oauth2 device flow profile configuration associated with this profile request",
                    getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }

        if (profileRequestContext.getInboundMessageContext() == null || !(profileRequestContext
                .getInboundMessageContext().getMessage() instanceof OAuth2DeviceAuthorizationRequest)) {
            log.error("{} No OAuth2DeviceAuthorizationRequest as inbound message", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        request = (OAuth2DeviceAuthorizationRequest) profileRequestContext.getInboundMessageContext().getMessage();
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        String deviceCode = idGeneratorLookupStrategy.apply(profileRequestContext).generateIdentifier(false);
        if (deviceCode.length() < deviceCodeLength) {
            log.error("{} Generated device code length is {}, profile configuration requires {}",
                    getLogPrefix(), deviceCode.length(), deviceCodeLength);
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_PROFILE_CONFIG);
            return;
        }
        deviceCode = deviceCode.substring(0, (int) deviceCodeLength);
        final String userCode = UserCodeSupport.generate((int) userCodeLength);
        final String rpId = rpCtx.getRelyingPartyId();
        final DeviceCodeObject deviceCodeObject = new DeviceCodeObject(deviceCode, new ClientID(rpId),
                getOidcResponseContext().getScope(), request.getAcrValues());
        try {
            log.debug("{} Storing device code of client {}, scope {}", getLogPrefix(), rpId,
                    deviceCodeObject.getScope());
            if (!deviceCodesCache.storeDeviceCode(deviceCodeObject, userCode, expiration.toMillis(),
                    interval.toSeconds() * 1000)) {
                log.error("{} Failed to set device code to cache.", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
                return;
            }
        } catch (final IOException e) {
            log.error("{} Failed to set device code to cache {}", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return;
        }
        final HttpServletResponse response = getHttpServletResponse();
        if (response == null) {
            log.error("{} Could not fetch HttpServletResponse", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_PROFILE_CONFIG);
            return;
        }
        HttpServletSupport.addNoCacheHeaders(response);
        final String uri = verificationURI != null ? verificationURI : buildVerificationURI();
        try {
            ((MessageContext) getOidcResponseContext().getParent())
                    .setMessage(new OAuth2DeviceAuthorizationSuccessResponse(deviceCode, userCode,
                            new URI(uri),
                            new URI(uri + (uri.contains("?") ? "&" : "?") + "user_code=" + userCode),
                            (int) expiration.toSeconds(), (int) interval.toSeconds()));
        } catch (final URISyntaxException e) {
            log.error("{} URI malformed {}", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return;
        }
    }

    /**
     * Build the verification URI from the request.
     *
     * @return verification URI
     */
    @Nonnull private String buildVerificationURI() {
        final HttpServletRequest httpRequest = getHttpServletRequest();
        assert httpRequest != null;
        final int port = httpRequest.getServerPort();
        return "https://" + httpRequest.getServerName() + (port == 80 || port == 443 || port <= 0 ? "" : ":" + port)
                + httpRequest.getContextPath() + authenticationEndpoint;
    }
}
