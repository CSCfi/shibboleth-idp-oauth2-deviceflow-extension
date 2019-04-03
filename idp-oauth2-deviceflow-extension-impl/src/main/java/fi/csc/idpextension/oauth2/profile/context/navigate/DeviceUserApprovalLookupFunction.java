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

package fi.csc.idpextension.oauth2.profile.context.navigate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.csc.idpextension.oauth2.messaging.context.DeviceUserAuthenticationContext;
import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;

/**
 * 
 */
@SuppressWarnings("rawtypes")
public class DeviceUserApprovalLookupFunction extends AbstractInitializableComponent
        implements ContextDataLookupFunction<MessageContext, Boolean> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DeviceUserApprovalLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    public Boolean apply(@Nullable MessageContext input) {
        if (input == null) {
            return false;
        }
        DeviceUserAuthenticationContext ctx = input.getSubcontext(DeviceUserAuthenticationContext.class);
        if (ctx == null) {
            return false;
        }
        return ctx.isUserApproved();
    }

}