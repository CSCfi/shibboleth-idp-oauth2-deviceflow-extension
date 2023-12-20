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

package fi.csc.shibboleth.plugin.oauth2.decoding.impl;

import java.io.IOException;

import javax.annotation.Nonnull;

import org.opensaml.messaging.decoder.MessageDecodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.JakartaServletUtils;

import fi.csc.shibboleth.plugin.oauth2.messaging.impl.BaseOAuth2RequestDecoder;
import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthorizationRequest;

/**
 * Message decoder decoding OAuth2 {@link OAuth2DeviceAuthorizationRequest}s.
 */
public class OAuth2DeviceAuthorizationRequestDecoder
        extends BaseOAuth2RequestDecoder<OAuth2DeviceAuthorizationRequest> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OAuth2DeviceAuthorizationRequestDecoder.class);

    /** {@inheritDoc} */
    @Override
    protected OAuth2DeviceAuthorizationRequest parseMessage() throws MessageDecodingException {
        try {
            final HTTPRequest httpReq = JakartaServletUtils.createHTTPRequest(getHttpServletRequest());
            getProtocolMessageLogger().trace("Inbound request {}", RequestUtil.toString(httpReq));
            return OAuth2DeviceAuthorizationRequest.parse(httpReq);
        } catch (final com.nimbusds.oauth2.sdk.ParseException | IOException e) {
            log.error("Unable to decode inbound request: {}", e.getMessage());
            throw new MessageDecodingException(e);
        }
    }

    @Override
    protected String getMessageToLog(OAuth2DeviceAuthorizationRequest message) {
        // TODO Auto-generated method stub
        return null;
    }

}