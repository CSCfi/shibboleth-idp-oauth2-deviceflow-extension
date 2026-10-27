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
import org.opensaml.profile.context.ProfileRequestContext;

import com.nimbusds.oauth2.sdk.Scope;

import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthorizationRequest;

/**
 * Returns a copy of the scope of the inbound device authorization request.
 */
public class DeviceAuthorizationRequestScopeLookupFunction
        implements ContextDataLookupFunction<ProfileRequestContext, Scope> {

    /** {@inheritDoc} */
    @Nullable
    public Scope apply(@Nullable final ProfileRequestContext input) {
        if (input == null) {
            return null;
        }
        final MessageContext inboundContext = input.getInboundMessageContext();
        if (inboundContext == null
                || !(inboundContext.getMessage() instanceof OAuth2DeviceAuthorizationRequest request)) {
            return null;
        }
        final Scope requested = request.getScope();
        if (requested == null) {
            return null;
        }
        final Scope scope = new Scope();
        scope.addAll(requested);
        return scope;
    }

}
