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

import net.shibboleth.idp.plugin.oidc.op.messaging.context.OIDCAuthenticationResponseContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.shared.logic.Constraint;

import org.opensaml.messaging.context.BaseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Action that adds an outbound {@link MessageContext} and related OIDC contexts to the {@link ProfileRequestContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 */
public abstract class AbstractInitializeOutboundResponseMessageContext extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractInitializeOutboundResponseMessageContext.class);

    /** Type of subcontext to create. */
    @Nonnull private Class<? extends BaseContext> contextType;
    
    /** Constructor. */
    public AbstractInitializeOutboundResponseMessageContext() {
        contextType = OIDCAuthenticationResponseContext.class;
    }
    
    /**
     * Set the type of subcontext to create.
     * 
     * @param claz context type
     */
    public void setContextType(@Nonnull final Class<? extends BaseContext> claz) {
        ifInitializedThrowUnmodifiabledComponentException();
        
        contextType = Constraint.isNotNull(claz, "Context type cannot be null");
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        final MessageContext msgCtx = new MessageContext();
        profileRequestContext.setOutboundMessageContext(msgCtx);
        msgCtx.ensureSubcontext(contextType);
        log.debug("{} Initialized outbound message context", getLogPrefix());
    }

}
