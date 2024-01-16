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

import javax.annotation.Nonnull;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.csc.shibboleth.plugin.oauth2.devicegrant.messaging.context.DeviceUserAuthenticationContext;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.DeviceEventIds;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Actions extracts user code from form. Extracted user code is stored to {@link DeviceUserAuthenticationContext} that
 * is placed under inbound message context.
 */
public class ExtractUserCodeFromFormRequest extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ExtractUserCodeFromFormRequest.class);

    /** Parameter name for username. */
    @Nonnull
    @NotEmpty
    private String userCodeFieldName;

    /** Constructor. */
    ExtractUserCodeFromFormRequest() {
        userCodeFieldName = "j_usercode";
    }

    /**
     * Set the user code parameter name.
     * 
     * @param fieldName the user code parameter name
     */
    public void setUserCodeFieldName(@Nonnull @NotEmpty final String fieldName) {
        checkSetterPreconditions();

        userCodeFieldName = Constraint.isNotNull(StringSupport.trimOrNull(fieldName),
                "User Code field name cannot be null or empty.");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.error("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.NO_USER_CODE);
            return;
        }
        final String userCode = request.getParameter(userCodeFieldName);
        if (userCode == null || userCode.isEmpty()) {
            log.error("{} No user code in request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.NO_USER_CODE);
            return;
        }
        DeviceUserAuthenticationContext ctx = new DeviceUserAuthenticationContext();
        ctx.setUserCode(userCode);
        log.debug("{} Initializing DeviceUserCodeContext for user code {}", getLogPrefix(), userCode);
        profileRequestContext.getInboundMessageContext().addSubcontext(ctx, true);
    }
}