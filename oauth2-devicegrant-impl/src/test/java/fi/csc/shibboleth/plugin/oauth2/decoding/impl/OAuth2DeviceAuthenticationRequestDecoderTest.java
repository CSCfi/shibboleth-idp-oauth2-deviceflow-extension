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

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.shared.primitive.NonnullSupplier;
import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthenticationRequest;

/**
 * Unit tests for {@link OAuth2DeviceAuthenticationRequestDecoder}.
 */
public class OAuth2DeviceAuthenticationRequestDecoderTest {

    private MockHttpServletRequest httpRequest;

    private OAuth2DeviceAuthenticationRequestDecoder decoder;

    @BeforeMethod
    protected void setUp() throws Exception {
        decoder = new OAuth2DeviceAuthenticationRequestDecoder();
        httpRequest = new MockHttpServletRequest();
        httpRequest.setMethod("GET");
        decoder.setHttpServletRequestSupplier(new NonnullSupplier<>() {
            public HttpServletRequest get() {
                return httpRequest;
            }
        });
        decoder.initialize();
    }

    @Test
    public void testRequestDecodingNoUserCode() throws MessageDecodingException {
        decoder.decode();
        MessageContext messageContext = decoder.getMessageContext();
        Assert.assertNull(((OAuth2DeviceAuthenticationRequest) messageContext.getMessage()).getUserCode());
    }

    @Test
    public void testRequestDecodingUserCode() throws MessageDecodingException {
        httpRequest.setQueryString("user_code=123456");
        decoder.decode();
        MessageContext messageContext = decoder.getMessageContext();
        Assert.assertEquals(((OAuth2DeviceAuthenticationRequest) messageContext.getMessage()).getUserCode(), "123456");
    }

}