/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Copied from Shib project /idp-oidc-extension-impl/src/main/java/net/shibboleth/idp/plugin/oidc/op/oauth2/decoding/impl/BaseOAuth2RequestDecoder.java
 */
package fi.csc.shibboleth.plugin.oauth2.messaging.impl;

import java.net.URI;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.decoder.servlet.AbstractHttpServletRequestMessageDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.Request;

/**
 * Base decoder for Nimbus OAuth2 request messages. 
 *
 * @param <T> The exact type of the request message, extends {@link Request}.
 */
public abstract class BaseOAuth2RequestDecoder<T extends Request> extends AbstractHttpServletRequestMessageDecoder {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(BaseOAuth2RequestDecoder.class);

    /** A flag to remove the IP address from the endpoint URI. */
    private boolean removeIpAddressFromEndpointUri;

    /** Constructor. */
    public BaseOAuth2RequestDecoder() {
        super();
        setProtocolMessageLoggerSubCategory("OAUTH2");
    }

    /**
     * Set the flag to remove the IP address from the endpoint URI.
     * 
     * @param flag What to set.
     */
    public synchronized void setRemoveIpAddressFromEndpointUri(final boolean flag) {
        ifInitializedThrowUnmodifiabledComponentException();
        ifDestroyedThrowDestroyedComponentException();

        removeIpAddressFromEndpointUri = flag;
    }

    /** {@inheritDoc} */
    @Override
    protected void doDecode() throws MessageDecodingException {
        final MessageContext messageContext = new MessageContext();
        final T requestMessage = parseMessage();
        messageContext.setMessage(requestMessage);
        setMessageContext(messageContext);
    }

    /**
     * Parses the message into the exact type of the request message.
     * 
     * @return The request message
     * @throws MessageDecodingException if there is a problem decoding the message context
     */
    @Nullable protected abstract T parseMessage() throws MessageDecodingException;
    
    /**
     * Get the string representation of what will be logged as the protocol message.
     * 
     * @param message the request message
     * @return the string representing the protocol message for logging purposes
     */
    @Nullable protected abstract String getMessageToLog(final T message);

    /** {@inheritDoc} */
    @Override
    @Nullable
    @SuppressWarnings("unchecked")
    protected String serializeMessageForLogging(@Nullable Object message) {
        return getMessageToLog((T) message);
    }

    /**
     * Returns the endpoint URI either from servlet request or from the given message, depending on the flag for
     * removing IP address from the endpoint URI.
     * 
     * @param message the message from which to take the endpoint URI (with IP address), if the flag is false
     * @return the endpoint URI
     */
    @Nullable protected String getEndpointURI(final T message) {
        if (removeIpAddressFromEndpointUri) {
            return getHttpServletRequest().getRequestURI();
        } else {
            final URI endpointUri = message.getEndpointURI();
            return endpointUri != null ? endpointUri.toString() : null;
        }
    }
}
