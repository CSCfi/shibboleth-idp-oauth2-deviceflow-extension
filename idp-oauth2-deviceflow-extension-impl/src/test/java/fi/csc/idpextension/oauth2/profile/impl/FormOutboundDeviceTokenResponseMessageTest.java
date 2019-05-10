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

import java.io.IOException;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.impl.MemoryStorageService;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import fi.csc.idpextension.oauth2.messaging.impl.OAuth2DeviceTokenRequest;
import fi.csc.idpextension.oauth2.profile.DeviceEventIds;
import fi.csc.idpextension.storage.DeviceCodeObject;
import fi.csc.idpextension.storage.DeviceCodesCache;
import fi.csc.idpextension.storage.DeviceStateObject;
import fi.csc.idpextension.storage.DeviceStateObject.State;
import junit.framework.Assert;
import net.minidev.json.parser.ParseException;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

/**
 * Unit tests for {@link FormOutboundDeviceTokenResponseMessage}.
 */
public class FormOutboundDeviceTokenResponseMessageTest {

    protected RequestContext requestCtx;

    @SuppressWarnings("rawtypes")
    protected ProfileRequestContext profileRequestCtx;

    private FormOutboundDeviceTokenResponseMessage action;

    private MemoryStorageService storageService;

    private DeviceCodesCache deviceCodesCache;

    private long expiresAt;

    @SuppressWarnings({"unchecked", "rawtypes"})
    @BeforeMethod
    protected void setUp() throws Exception {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        profileRequestCtx.setInboundMessageContext(new MessageContext());
        profileRequestCtx.getInboundMessageContext().setMessage(new OAuth2DeviceTokenRequest(null,
                new ClientID("clientID"), OAuth2DeviceTokenRequest.grantTypeValue, "DC123456"));
        profileRequestCtx.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        profileRequestCtx.setOutboundMessageContext(new MessageContext());
        profileRequestCtx.getOutboundMessageContext().getSubcontext(OIDCAuthenticationResponseContext.class, true);
        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.initialize();
        deviceCodesCache = new DeviceCodesCache();
        deviceCodesCache.setStorage(storageService);
        deviceCodesCache.initialize();
        deviceCodesCache.storeDeviceCode(new DeviceCodeObject("DC123456", new ClientID("clientID"), null), "UC123456",
                100000);
        expiresAt = System.currentTimeMillis() + 100000;
        deviceCodesCache.updateDeviceState("DC123456", new DeviceStateObject(State.APPROVED, "AT123456", expiresAt),
                100000);
        action = new FormOutboundDeviceTokenResponseMessage();
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        action.setHttpServletRequest(httpRequest);
        action.setDeviceCodesCache(deviceCodesCache);
        action.initialize();
    }

    @AfterMethod
    protected void tearDown() {
        deviceCodesCache.destroy();
        deviceCodesCache = null;
        storageService.destroy();
        storageService = null;
    }

    @Test
    public void testSuccess() throws IOException, ParseException {
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        AccessTokenResponse resp = (AccessTokenResponse) profileRequestCtx.getOutboundMessageContext().getMessage();
        Assert.assertEquals("AT123456", resp.getTokens().getAccessToken().getValue());
        Assert.assertEquals(expiresAt, resp.getTokens().getAccessToken().getLifetime());
    }

    @Test
    public void testPending() throws IOException, ParseException {
        deviceCodesCache.updateDeviceState("DC123456", new DeviceStateObject(State.PENDING, null, null), 100000);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.AUTHORIZATION_PENDING);
    }

    @Test
    public void testDenied() throws IOException, ParseException {
        deviceCodesCache.updateDeviceState("DC123456", new DeviceStateObject(State.DENIED, null, null), 100000);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.USER_DENIED);
    }

    @Test
    public void testExpired() throws IOException, ParseException {
        deviceCodesCache.updateDeviceState("DC123456", new DeviceStateObject(State.PENDING, null, null), 0);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.EXPIRED_TOKEN);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNoMessage() throws IOException, ParseException {
        profileRequestCtx.getInboundMessageContext().setMessage(null);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MSG_CTX);
    }
}