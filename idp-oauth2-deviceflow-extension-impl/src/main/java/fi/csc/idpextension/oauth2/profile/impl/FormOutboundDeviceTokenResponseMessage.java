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

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.profile.impl.AbstractOIDCResponseAction;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;

import fi.csc.idpextension.oauth2.messaging.impl.OAuth2DeviceTokenRequest;
import fi.csc.idpextension.storage.DeviceCodesCache;
import fi.csc.idpextension.storage.DeviceStateObject;
import fi.csc.idpextension.storage.DeviceStateObject.State;
import net.minidev.json.parser.ParseException;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that forms outbound token revocation success message. Formed message is set to
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 */

@SuppressWarnings("rawtypes")
public class FormOutboundDeviceTokenResponseMessage extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(FormOutboundDeviceTokenResponseMessage.class);

    @NonnullAfterInit
    private DeviceCodesCache deviceCodesCache;

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
    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        // blatant!
        OAuth2DeviceTokenRequest request =
                (OAuth2DeviceTokenRequest) profileRequestContext.getInboundMessageContext().getMessage();
        String deviceCode = request.getDeviceCode();
        try {
            DeviceStateObject stateObject = deviceCodesCache.getDeviceState(deviceCode);
            State state = stateObject.getState();
            log.debug("StateObject {} {} {} {}", stateObject.getState(), stateObject.getAccessToken(),
                    stateObject.getExpiresAt());
            if (state == State.APPROVED && stateObject.getAccessToken() != null) {
                AccessToken accesToken =
                        new BearerAccessToken(stateObject.getAccessToken(), stateObject.getExpiresAt(), null);
                AccessTokenResponse response = new AccessTokenResponse(new Tokens(accesToken, null));
                ((MessageContext) getOidcResponseContext().getParent()).setMessage(response);
                return;
            }

        } catch (IOException | ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }
}