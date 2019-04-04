/*
 * Copyright (c) 2019 CSC- IT Center for Science, www.csc.fi
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

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.profile.impl.AbstractOIDCResponseAction;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

import fi.csc.idpextension.oauth2.config.OAuth2DeviceFlowConfiguration;
import fi.csc.idpextension.oauth2.messaging.impl.OAuth2DeviceAuthorizationRequest;
import fi.csc.idpextension.oauth2.messaging.impl.OAuth2DeviceAuthorizationSuccessResponse;
import fi.csc.idpextension.storage.DeviceCodeObject;
import fi.csc.idpextension.storage.DeviceCodesCache;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;

@SuppressWarnings("rawtypes")
public class FormOutboundDeviceAuthorizationResponseMessage extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(FormOutboundDeviceAuthorizationResponseMessage.class);

    @NonnullAfterInit
    private DeviceCodesCache deviceCodesCache;

    /** Strategy used to locate the {@link IdentifierGenerationStrategy} to use. */
    @Nonnull
    private Function<ProfileRequestContext, IdentifierGenerationStrategy> idGeneratorLookupStrategy;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Length of the device code. */
    private long deviceCodeLength;

    /** Length of the user code. */
    private long userCodeLength;

    /** Expiration of device/user codes in milliseconds. */
    private long expiration;

    /** Relying party context. */
    private RelyingPartyContext rpCtx;

    /** Authentication endpoint not including server name and protocol. */
    private String authenticationEndpoint = "/idp/profile/oauth2/device/authenticate";

    /**
     * Inbound request. Nonnull after pre-execute.
     */
    @NonnullAfterInit
    private OAuth2DeviceAuthorizationRequest request;

    public FormOutboundDeviceAuthorizationResponseMessage() {
        idGeneratorLookupStrategy = new Function<ProfileRequestContext, IdentifierGenerationStrategy>() {
            public IdentifierGenerationStrategy apply(ProfileRequestContext input) {
                return new SecureRandomIdentifierGenerationStrategy();
            }
        };
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
    }

    /**
     * Set authentication endpoint not including server name and protocol.
     * 
     * @param endpoint authentication endpoint not including server name and protocol
     */
    public void setAuthenticationEndpoint(String endpoint) {
        authenticationEndpoint = endpoint;
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
     * Set the revocation cache instance to use.
     * 
     * @param cache The revocationCache to set.
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

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

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
        if (pc instanceof OAuth2DeviceFlowConfiguration) {
            deviceCodeLength = ((OAuth2DeviceFlowConfiguration) pc).getDeviceCodeLength();
            userCodeLength = ((OAuth2DeviceFlowConfiguration) pc).getUserCodeLength();
            expiration = ((OAuth2DeviceFlowConfiguration) pc).getDeviceCodeLifetime();
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
    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        String deviceCode = idGeneratorLookupStrategy.apply(profileRequestContext).generateIdentifier();
        if (deviceCode.length() <= deviceCodeLength) {
            log.error("{} Generated device code length is {}, expected length by profile config is {}+1",
                    getLogPrefix(), deviceCode.length(), deviceCodeLength);
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_PROFILE_CONFIG);
            return;
        }
        deviceCode = deviceCode.substring(1, (int) deviceCodeLength + 1);
        String userCode = idGeneratorLookupStrategy.apply(profileRequestContext).generateIdentifier();
        if (userCode.length() <= userCodeLength) {
            log.error("{} Generated user code length is {}, expected length by profile config is {}+1", getLogPrefix(),
                    userCode.length(), userCodeLength);
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_PROFILE_CONFIG);
            return;
        }
        userCode = userCode.substring(1, (int) userCodeLength + 1);
        String rpId = rpCtx.getRelyingPartyId();
        DeviceCodeObject deviceCodeObject =
                new DeviceCodeObject(deviceCode, new ClientID(rpId), new Scope(request.getScope()));
        try {
            log.debug("Storing device flow device code object {} per user code {}",
                    deviceCodeObject.toJSONObject().toString(), userCode);
            if (!deviceCodesCache.storeDeviceCode(deviceCodeObject, userCode, expiration)) {
                log.error("{} Failed to set device code to cache.", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
                return;
            }
        } catch (IOException e) {
            log.error("{} Failed to set device code to cache {}", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return;
        }
        try {
            ((MessageContext) getOidcResponseContext().getParent())
                    .setMessage(new OAuth2DeviceAuthorizationSuccessResponse(deviceCode, userCode,
                            new URI("https://" + getHttpServletRequest().getServerName() + authenticationEndpoint),
                            new URI("https://" + getHttpServletRequest().getServerName() + authenticationEndpoint
                                    + "?user_code=" + userCode),
                            (int) expiration / 1000, null));
        } catch (URISyntaxException e) {
            log.error("{} URI malformed {}", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return;
        }
    }
}