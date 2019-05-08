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

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.id.ClientID;

import fi.csc.idpextension.storage.DeviceCodeObject;
import fi.csc.idpextension.storage.DeviceCodesCache;
import net.minidev.json.parser.ParseException;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * ClientID lookup function for Authentication end point. The lookup locates a {@link DeviceCodeObject} from
 * {@DeviceCodesCache} by user code and returns {@link DeviceCodeObject#getClientID()}
 */
@SuppressWarnings("rawtypes")
public class DeviceClientIDLookupFunction extends AbstractInitializableComponent
        implements ContextDataLookupFunction<MessageContext, ClientID> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DeviceClientIDLookupFunction.class);

    /** Strategy to locate user code. */
    @Nonnull
    private Function<MessageContext, String> userCodeLookupStrategy;

    /** Cache for device codes. */
    @NonnullAfterInit
    private DeviceCodesCache deviceCodesCache;

    /**
     * Constructor.
     */
    public DeviceClientIDLookupFunction() {
        userCodeLookupStrategy = new DeviceUserCodeLookupFunction();
    }

    /**
     * Set strategy to locate user code.
     * 
     * @param strategy Strategy to locate user code
     */
    public void setDeviceUserCodeLookupStrategy(@Nonnull final Function<MessageContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        userCodeLookupStrategy =
                Constraint.isNotNull(strategy, "DeviceUserCodeLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set cache for device codes.
     * 
     * @param cache Cache for device codes
     */
    public void setDeviceCodesCache(@Nonnull final DeviceCodesCache cache) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        deviceCodesCache = Constraint.isNotNull(cache, "DeviceCodesCache cannot be null");
    }

    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        Constraint.isNotNull(deviceCodesCache, "DeviceCodesCache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    public ClientID apply(@Nullable MessageContext input) {
        if (input == null) {
            return null;
        }
        String userCode = userCodeLookupStrategy.apply(input);
        if (userCode == null) {
            return null;
        }
        DeviceCodeObject obj = null;
        try {
            obj = deviceCodesCache.getDeviceCode(userCode);
        } catch (IOException | ParseException e) {
            log.error("Exception occurred while accessing Device Code Cache {}", e);
        }
        if (obj == null) {
            log.warn("No device code matching user code {}", userCode);
            return null;
        }
        return obj.getClientID();
    }

}