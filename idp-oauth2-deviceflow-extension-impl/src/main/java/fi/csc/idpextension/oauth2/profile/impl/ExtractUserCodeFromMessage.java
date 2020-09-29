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

import java.util.function.Function;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.csc.idpextension.oauth2.messaging.context.DeviceUserAuthenticationContext;
import fi.csc.idpextension.oauth2.profile.DeviceEventIds;
import fi.csc.idpextension.oauth2.profile.context.navigate.DeviceUserCodeLookupFunction;
import net.shibboleth.idp.profile.AbstractProfileAction;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.ActionSupport;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Actions extracts user code from message. Extracted user code is stored to {@link DeviceUserAuthenticationContext}
 * that is placed under inbound message context. The action should be called as the first action to try the extracting
 * of the user code.
 */
public class ExtractUserCodeFromMessage extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ExtractUserCodeFromMessage.class);

    private String userCode;

    @Nonnull
    private Function<MessageContext, String> userCodeLookupStrategy;

    public void setDeviceUserCodeLookupStrategy(@Nonnull final Function<MessageContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        userCodeLookupStrategy =
                Constraint.isNotNull(strategy, "DeviceUserCodeLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Constructor.
     */
    public ExtractUserCodeFromMessage() {
        userCodeLookupStrategy = new DeviceUserCodeLookupFunction();
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        userCode = userCodeLookupStrategy.apply(profileRequestContext.getInboundMessageContext());
        if (userCode == null) {
            log.debug("{} No user code available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.NO_USER_CODE);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        DeviceUserAuthenticationContext ctx = new DeviceUserAuthenticationContext();
        ctx.setUserCode(userCode);
        log.debug("{} Initializing DeviceUserCodeContext for user code {}", getLogPrefix(), userCode);
        profileRequestContext.getInboundMessageContext().addSubcontext(ctx, true);

    }
}