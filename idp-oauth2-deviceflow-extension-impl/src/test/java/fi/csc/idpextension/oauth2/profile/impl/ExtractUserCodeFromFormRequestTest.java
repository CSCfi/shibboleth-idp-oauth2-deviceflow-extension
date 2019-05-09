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

import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import fi.csc.idpextension.oauth2.messaging.context.DeviceUserAuthenticationContext;
import fi.csc.idpextension.oauth2.profile.DeviceEventIds;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link ExtractUserCodeFromFormRequest}.
 */
public class ExtractUserCodeFromFormRequestTest {

    private MockHttpServletRequest httpRequest;

    protected RequestContext requestCtx;

    @SuppressWarnings("rawtypes")
    protected ProfileRequestContext profileRequestCtx;

    private ExtractUserCodeFromFormRequest action;

    @BeforeMethod
    protected void setUp() throws Exception {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        httpRequest = new MockHttpServletRequest();
        httpRequest.addParameter("j_usercode", "123456");
        action = new ExtractUserCodeFromFormRequest();
        action.setHttpServletRequest(httpRequest);
        action.initialize();
    }

    @Test
    public void testSuccess() throws MessageDecodingException {
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertEquals(((DeviceUserAuthenticationContext) profileRequestCtx.getInboundMessageContext()
                .getSubcontext(DeviceUserAuthenticationContext.class)).getUserCode(), "123456");
    }

    @Test
    public void testNoHttpRequest() throws MessageDecodingException, ComponentInitializationException {
        action = new ExtractUserCodeFromFormRequest();
        action.initialize();
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.NO_USER_CODE);
    }

    @Test
    public void testNoUserCode() throws MessageDecodingException {
        httpRequest.removeAllParameters();
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.NO_USER_CODE);
    }

    @Test
    public void testEmptyUserCode() throws MessageDecodingException {
        httpRequest.removeAllParameters();
        httpRequest.addParameter("j_usercode", "");
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.NO_USER_CODE);
    }
    
    @Test
    public void testUserCodeFieldName() throws MessageDecodingException, ComponentInitializationException {
        httpRequest.removeAllParameters();
        httpRequest.addParameter("j_usercode_newfield", "123456");
        action = new ExtractUserCodeFromFormRequest();
        action.setUserCodeFieldName("j_usercode_newfield");
        action.setHttpServletRequest(httpRequest);
        action.initialize();
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertEquals(((DeviceUserAuthenticationContext) profileRequestCtx.getInboundMessageContext()
                .getSubcontext(DeviceUserAuthenticationContext.class)).getUserCode(), "123456");
    }

}