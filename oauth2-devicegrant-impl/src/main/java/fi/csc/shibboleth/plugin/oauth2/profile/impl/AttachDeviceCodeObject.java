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
import java.util.function.Function;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.csc.shibboleth.plugin.oauth2.devicegrant.messaging.context.DeviceUserAuthenticationContext;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.DeviceEventIds;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.context.navigate.DeviceUserCodeLookupFunction;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodeObject;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodesCache;
import net.minidev.json.parser.ParseException;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;

/**
 * Actions extracts user code from message. Extracted user code is stored to
 * {@link DeviceUserAuthenticationContext} that is placed under inbound message
 * context. The action should be called as the first action to try the
 * extracting of the user code.
 */
public class AttachDeviceCodeObject extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AttachDeviceCodeObject.class);

    private String userCode;

    /** Cache for device codes. */
    @NonnullAfterInit
    private DeviceCodesCache deviceCodesCache;

    @Nonnull
    private Function<MessageContext, String> userCodeLookupStrategy;

    /** Device user authentication context. */
    private DeviceUserAuthenticationContext ctx;

    /**
     * Constructor.
     */
    public AttachDeviceCodeObject() {
        userCodeLookupStrategy = new DeviceUserCodeLookupFunction();
    }

    public void setDeviceUserCodeLookupStrategy(@Nonnull final Function<MessageContext, String> strategy) {
        checkSetterPreconditions();
        userCodeLookupStrategy = Constraint.isNotNull(strategy,
                "DeviceUserCodeLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set cache for device codes.
     * 
     * @param cache Cache for device codes
     */
    public void setDeviceCodesCache(@Nonnull final DeviceCodesCache cache) {
        checkSetterPreconditions();
        deviceCodesCache = Constraint.isNotNull(cache, "DeviceCodesCache cannot be null");
    }

    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        Constraint.isNotNull(deviceCodesCache, "DeviceCodesCache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        userCode = userCodeLookupStrategy.apply(profileRequestContext.getInboundMessageContext());
        if (userCode == null) {
            log.error("{} No user code available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.NO_USER_CODE);
            return false;
        }
        ctx = profileRequestContext.getInboundMessageContext().getSubcontext(DeviceUserAuthenticationContext.class);
        if (ctx == null) {
            log.error("{} No device user authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        DeviceCodeObject obj = null;
        try {
            obj = deviceCodesCache.getDeviceCode(userCode);
        } catch (IOException | ParseException e) {
            log.error("() Exception occurred while accessing Device Code Cache {}", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return;
        }
        if (obj == null) {
            log.error("() No device code object matching user code {}", getLogPrefix(), userCode);
            ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.INVALID_USER_CODE);
            return;
        }
        ctx.setDeviceCodeObject(obj);
    }
}