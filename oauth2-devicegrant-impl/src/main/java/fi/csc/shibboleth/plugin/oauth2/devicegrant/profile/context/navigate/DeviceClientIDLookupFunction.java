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

package fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.context.navigate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.id.ClientID;

import fi.csc.shibboleth.plugin.oauth2.devicegrant.messaging.context.DeviceUserAuthenticationContext;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodeObject;
import net.shibboleth.shared.component.AbstractInitializableComponent;

/**
 * ClientID lookup function for Authentication end point. The lookup locates a
 * {@link DeviceCodeObject} from {DeviceUserAuthenticationContext} by user code
 * and returns {@link DeviceCodeObject#getClientID()}
 */
public class DeviceClientIDLookupFunction extends AbstractInitializableComponent
        implements ContextDataLookupFunction<MessageContext, ClientID> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DeviceClientIDLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    public ClientID apply(@Nullable MessageContext input) {
        if (input == null) {
            return null;
        }
        DeviceUserAuthenticationContext ctx = input.getSubcontext(DeviceUserAuthenticationContext.class);
        if (ctx == null) {
            return null;
        }
        return ctx.getDeviceCodeObject().getClientID();
    }
}