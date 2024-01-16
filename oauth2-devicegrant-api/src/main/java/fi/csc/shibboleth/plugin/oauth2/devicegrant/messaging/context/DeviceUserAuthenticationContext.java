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

package fi.csc.shibboleth.plugin.oauth2.devicegrant.messaging.context;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.opensaml.messaging.context.BaseContext;

import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodeObject;
import net.shibboleth.shared.logic.Constraint;

/**
 * Subcontext carrying user code and user approval status. This context appears
 * as a subcontext of the inbound {@link MessageContext}.
 */
public class DeviceUserAuthenticationContext extends BaseContext {

    /**
     * The end-user verification code described in
     * https://tools.ietf.org/html/rfc8628#section-3.2.
     */
    private String userCode;

    /**
     * Whether user has approved or denied request described in
     * https://tools.ietf.org/html/rfc8628#section-3.3.
     */
    private boolean userApproved;

    /** Device code object matching user code. */
    private DeviceCodeObject deviceCodeObject;

    /**
     * Get whether user has approved or denied request.
     * 
     * @return true if user has approved the request, otherwise false.
     */
    public boolean isUserApproved() {
        return userApproved;
    }

    /**
     * Set whether user has approved or denied request.
     * 
     * @param userApproved true if user has approved the request, otherwise false.
     */
    public void setUserApproved(boolean userApproved) {
        this.userApproved = userApproved;
    }

    /**
     * Get the end-user verification code.
     * 
     * @return The end-user verification code
     */
    @Nullable
    public String getUserCode() {
        return userCode;
    }

    /**
     * Set the end-user verification code.
     * 
     * @param code The end-user verification code
     */
    public void setUserCode(@Nonnull String code) {
        Constraint.isNotNull(code, "User code must not be null");
        userCode = code;
    }

    /**
     * Get device code object matching user code.
     * 
     * @return device code object matching user code
     */
    public DeviceCodeObject getDeviceCodeObject() {
        return deviceCodeObject;
    }

    /**
     * Set device code object matching user code.
     * 
     * @param deviceCodeObject device code object matching user code.
     */
    public void setDeviceCodeObject(@Nonnull DeviceCodeObject object) {
        Constraint.isNotNull(object, "Device code must not be null");
        deviceCodeObject = object;
    }
}