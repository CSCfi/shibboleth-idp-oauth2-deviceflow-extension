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

package fi.csc.idpextension.oauth2.decoding.impl;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import fi.csc.idpextension.oauth2.messaging.impl.OAuth2DeviceTokenRequest;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link OAuth2DeviceTokenRequestDecoder}.
 */
public class OAuth2DeviceTokenRequestDecoderTest {

    private MockHttpServletRequest httpRequest;

    private OAuth2DeviceTokenRequestDecoder decoder;

    @BeforeMethod
    protected void setUp() throws Exception {
        httpRequest = new MockHttpServletRequest();
        httpRequest.setMethod("POST");
        httpRequest.addHeader("Content-Type", "application/x-www-form-urlencoded");
        httpRequest.addParameter("client_id", "123456");
        httpRequest.addParameter("device_code", "123456");
        httpRequest.addParameter("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
        decoder = new OAuth2DeviceTokenRequestDecoder();
        decoder.setHttpServletRequest(httpRequest);
        decoder.initialize();
    }

    @Test
    public void testRequestDecoding() throws MessageDecodingException {
        decoder.decode();
        MessageContext<OAuth2DeviceTokenRequest> messageContext = decoder.getMessageContext();
        Assert.assertEquals(messageContext.getMessage().getClientID().toString(), "123456");
    }

    @Test(expectedExceptions = MessageDecodingException.class)
    public void testInvalidRequestDecoding() throws MessageDecodingException {
        httpRequest.removeParameter("client_id");
        decoder.decode();
    }

    // TODO: Remove as unrelated as the message class gets it's own tests
    @Test
    public void testClientInHeaders() throws MessageDecodingException, ComponentInitializationException {
        httpRequest.addHeader("Authorization", "Basic dGVzdDp0ZXN0");
        httpRequest.removeParameter("client_id");
        decoder = new OAuth2DeviceTokenRequestDecoder();
        decoder.setHttpServletRequest(httpRequest);
        decoder.initialize();
        decoder.decode();
        MessageContext<OAuth2DeviceTokenRequest> messageContext = decoder.getMessageContext();
        Assert.assertEquals(messageContext.getMessage().getClientAuthentication().getClientID().getValue(), "test");
    }
}