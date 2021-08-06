/*
 * Copyright (c) 2019-2021 CSC- IT Center for Science, www.csc.fi
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

import java.util.Set;
import javax.annotation.Nonnull;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;

import fi.csc.idpextension.oauth2.messaging.impl.OAuth2DeviceTokenRequest;
import net.shibboleth.idp.plugin.oidc.op.messaging.context.OIDCMetadataContext;
import net.shibboleth.idp.plugin.oidc.op.profile.OidcEventIds;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An action that validates the grant type is registered to the requesting RP and is of expected type. For example in
 * Device Flow the grant type is expected to be urn:ietf:params:oauth:grant-type:device_code. Action does not check the
 * existence or value of the grant in the actual request.
 */
public class ValidateGrantType extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateGrantType.class);

    @Nonnull
    private String expectedGrantType = OAuth2DeviceTokenRequest.grantTypeValue;

    /** OIDC Metadata context. */
    private OIDCMetadataContext oidcMetadataContext;

    /**
     * Set expected grant type.
     * 
     * @param type expected grant type
     */
    public void setExpectedGrantType(@Nonnull String type) {
        Constraint.isNotEmpty(type, "Expected grant type must not be null or empty");
        expectedGrantType = type;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        if (profileRequestContext.getInboundMessageContext() == null) {
            log.error("{} No inbound message context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        oidcMetadataContext =
                profileRequestContext.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, false);
        if (oidcMetadataContext == null) {
            log.error("{} No metadata found for relying party", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final Set<GrantType> registeredTypes = oidcMetadataContext.getClientInformation().getMetadata().getGrantTypes();
        try {
            if (registeredTypes == null || registeredTypes.isEmpty()
                    || !registeredTypes.contains(GrantType.parse(expectedGrantType))) {
                log.error("{} The grant type {} is not registered for this RP", getLogPrefix(), expectedGrantType);
                ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT_TYPE);
            }
        } catch (ParseException e) {
            log.error("{} Unable to parse grant type from {}", getLogPrefix(), expectedGrantType);
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT_TYPE);
        }
    }
}
