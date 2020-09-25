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

package fi.csc.idpextension.oauth2.profile.context.navigate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.csc.idpextension.oauth2.messaging.context.DeviceUserAuthenticationContext;
import fi.csc.idpextension.oauth2.messaging.impl.OAuth2DeviceAuthenticationRequest;
import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;

/**
 * Primarily locates user code from {@link DeviceUserAuthenticationContext#getUserCode()}.
 * {@link DeviceUserAuthenticationContext} is assumed to reside under {@link MessageContext}. The authentication request
 * {@link OAuth2DeviceAuthenticationRequest} of the {@link MessageContext} is the secondary source for the information.
 * If both fail to produce the value, a null is returned.
 */
public class DeviceUserCodeLookupFunction extends AbstractInitializableComponent
        implements ContextDataLookupFunction<MessageContext, String> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DeviceUserCodeLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    public String apply(@Nullable MessageContext input) {
        if (input == null) {
            return null;
        }
        DeviceUserAuthenticationContext ctx = input.getSubcontext(DeviceUserAuthenticationContext.class);
        if (ctx != null) {
            return ctx.getUserCode();
        }
        Object message = input.getMessage();
        if (!(message instanceof OAuth2DeviceAuthenticationRequest)) {
            return null;
        }
        return ((OAuth2DeviceAuthenticationRequest) message).getUserCode();
    }

}