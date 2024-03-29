/*
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

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.plugin.oidc.op.messaging.context.OIDCAuthenticationResponseContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.oidc.metadata.context.OIDCMetadataContext;

/**
 * Abstract class for actions performing actions on {@link OIDCAuthenticationResponseContext} located under
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 */
public abstract class AbstractOIDCResponseAction extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AbstractOIDCResponseAction.class);

    /** oidc response context. */
    @Nonnull
    private OIDCAuthenticationResponseContext oidcResponseContext;

    /** OIDC Metadata context. */
    @Nonnull
    private OIDCMetadataContext oidcMetadataContext;

    /**
     * Returns oidc response context.
     * 
     * @return ctx.
     */
    @Nonnull
    public OIDCAuthenticationResponseContext getOidcResponseContext() {
        return oidcResponseContext;
    }

    /**
     * Returns the OIDC Metadata context.
     * 
     * @return The OIDC Metadata context.
     */
    public OIDCMetadataContext getMetadataContext() {
        return oidcMetadataContext;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        final MessageContext outboundMessageCtx = profileRequestContext.getOutboundMessageContext();
        if (outboundMessageCtx == null) {
            log.error("{} No outbound message context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        oidcResponseContext = outboundMessageCtx.getSubcontext(OIDCAuthenticationResponseContext.class);
        if (oidcResponseContext == null) {
            log.error("{} No oidc response context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        oidcMetadataContext = profileRequestContext.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class);
        
        return true;
    }

}