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

package fi.csc.idpextension.oauth2.profile.impl;

import java.util.Set;
import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;

import net.shibboleth.idp.profile.AbstractProfileAction;

/**
 * An action that validates the grant type is registered to the requesting RP. This action is used in Token end point to
 * check if urn:ietf:params:oauth:grant-type:device_code been registered to be used as a grant.
 */
@SuppressWarnings("rawtypes")
public class ValidateGrantType extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateGrantType.class);

    /** OIDC Metadata context. */
    @Nonnull
    private OIDCMetadataContext oidcMetadataContext;

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
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
        // TODO: grant value to be compared with setter method
        // "urn:ietf:params:oauth:grant-type:device_code" -> setter/getter
        final Set<GrantType> registeredTypes = oidcMetadataContext.getClientInformation().getMetadata().getGrantTypes();
        try {
            if (registeredTypes == null || registeredTypes.isEmpty()
                    || !registeredTypes.contains(GrantType.parse("urn:ietf:params:oauth:grant-type:device_code"))) {
                log.error("{} The grant type {} is not registered for this RP", getLogPrefix(),
                        "urn:ietf:params:oauth:grant-type:device_code");
                ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT_TYPE);
            }
        } catch (ParseException e) {
            log.error("{} Unable to parse grant type from {}", getLogPrefix(),
                    "urn:ietf:params:oauth:grant-type:device_code");
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT_TYPE);
        }

    }
}
