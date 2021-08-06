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

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.idp.plugin.oidc.op.profile.impl.AbstractInitializeOutboundResponseMessageContext;

/**
 * Action that adds an outbound {@link MessageContext} and related OIDC contexts to the {@link ProfileRequestContext}
 * not knowing the relying party yet.
 *
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 */
public class InitializeOutboundDeviceAuthorizationResponseMessageContext
        extends AbstractInitializeOutboundResponseMessageContext {

}