/*
 * Copyright (c) 2024 CSC- IT Center for Science, www.csc.fi
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
package fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.context.navigate;

import javax.annotation.Nullable;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;

import com.nimbusds.oauth2.sdk.AbstractOptionallyAuthenticatedRequest;
import com.nimbusds.oauth2.sdk.AbstractOptionallyIdentifiedRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;

import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthorizationRequest;
import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceTokenRequest;

/**
 * A function that returns client id of the authentication request via a lookup
 * function. This lookup locates client id from oauth2 device grant
 * authorization request client authentication or from request parameter if
 * available. If information is not available, null is returned.
 */
public class APIRequestClientIDLookupFunction implements ContextDataLookupFunction<MessageContext, ClientID> {

    /** {@inheritDoc} */
    @Nullable
    public ClientID apply(@Nullable final MessageContext input) {
        if (input == null) {
            return null;
        }
        final Object message = input.getMessage();
        if (!(message instanceof OAuth2DeviceAuthorizationRequest) && !(message instanceof OAuth2DeviceTokenRequest)) {
            return null;
        }
        final AbstractOptionallyAuthenticatedRequest req = (AbstractOptionallyAuthenticatedRequest) message;
        if (req.getClientAuthentication() != null && req.getClientAuthentication().getClientID() != null) {
            return req.getClientAuthentication().getClientID();
        }
        if (!(message instanceof AbstractOptionallyIdentifiedRequest)) {
            return null;
        }
        return ((AbstractOptionallyIdentifiedRequest) req).getClientID();
    }

}
