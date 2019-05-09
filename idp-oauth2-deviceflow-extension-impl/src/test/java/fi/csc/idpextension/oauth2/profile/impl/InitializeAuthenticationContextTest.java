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

import javax.security.auth.Subject;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

/**
 * Unit tests for {@link InitializeAuthenticationContext}.
 */
public class InitializeAuthenticationContextTest {

    protected RequestContext requestCtx;

    @SuppressWarnings("rawtypes")
    protected ProfileRequestContext profileRequestCtx;

    private InitializeAuthenticationContext action;

    @BeforeMethod
    protected void setUp() throws Exception {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        action = new InitializeAuthenticationContext();
        action.initialize();
    }

    @Test
    public void testSuccess() throws MessageDecodingException {
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertNotNull(profileRequestCtx.getSubcontext(AuthenticationContext.class));
    }

    @Test
    public void testSuccessExistingResult() throws MessageDecodingException {
        AuthenticationContext ctx = new AuthenticationContext();
        ctx.setAuthenticationResult(new AuthenticationResult("testID", new Subject()));
        profileRequestCtx.addSubcontext(ctx);
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertNotNull(profileRequestCtx.getSubcontext(AuthenticationContext.class));
        Assert.assertEquals("testID",
                ((AuthenticationContext) profileRequestCtx.getSubcontext(AuthenticationContext.class))
                        .getInitialAuthenticationResult().getAuthenticationFlowId());
    }
}