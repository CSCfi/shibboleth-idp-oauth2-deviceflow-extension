/*
 * Copyright (c) 2019-2020 CSC- IT Center for Science, www.csc.fi
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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.impl.MemoryStorageService;
import org.springframework.core.io.ClassPathResource;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import fi.csc.idpextension.oauth2.config.OAuth2DeviceFlowConfiguration;
import fi.csc.idpextension.oauth2.messaging.context.DeviceUserAuthenticationContext;
import fi.csc.idpextension.storage.DeviceCodeObject;
import fi.csc.idpextension.storage.DeviceCodesCache;
import fi.csc.idpextension.storage.DeviceStateObject;
import net.minidev.json.parser.ParseException;
import net.shibboleth.ext.spring.resource.ResourceHelper;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.impl.BasicKeystoreKeyStrategy;
import net.shibboleth.utilities.java.support.security.DataSealer;

/**
 * Unit tests for {@link StoreDeviceState}.
 */
public class StoreDeviceStateTest {

    protected RequestContext requestCtx;

    protected ProfileRequestContext profileRequestCtx;

    private StoreDeviceState action;

    private MemoryStorageService storageService;

    private DeviceCodesCache deviceCodesCache;

    private DeviceUserAuthenticationContext deviceUserAuthenticationContext;

    @BeforeMethod
    protected void setUp() throws Exception {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        profileRequestCtx.setInboundMessageContext(new MessageContext());
        profileRequestCtx.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        deviceUserAuthenticationContext =
                profileRequestCtx.getInboundMessageContext().getSubcontext(DeviceUserAuthenticationContext.class, true);
        deviceUserAuthenticationContext.setUserCode("UC123456");
        deviceUserAuthenticationContext.setUserApproved(true);
        profileRequestCtx.setOutboundMessageContext(new MessageContext());
        OIDCAuthenticationResponseContext respCtx = profileRequestCtx.getOutboundMessageContext()
                .getSubcontext(OIDCAuthenticationResponseContext.class, true);
        respCtx.setSubject("sub");
        respCtx.setScope(new Scope());
        respCtx.setAuthTime(Instant.ofEpochMilli(0));
        ((RelyingPartyContext) profileRequestCtx.getSubcontext(RelyingPartyContext.class, true))
                .setProfileConfig((new OAuth2DeviceFlowConfiguration()));
        ((SubjectContext) profileRequestCtx.getSubcontext(SubjectContext.class, true))
                .setPrincipalName("principalName");
        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.initialize();
        deviceCodesCache = new DeviceCodesCache();
        deviceCodesCache.setStorage(storageService);
        deviceCodesCache.initialize();
        deviceCodesCache.storeDeviceCode(new DeviceCodeObject("DC123456", new ClientID("clientID"), null), "UC123456",
                100000);
        action = new StoreDeviceState(getDataSealer());
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

    public DataSealer getDataSealer() throws ComponentInitializationException, NoSuchAlgorithmException {
        final BasicKeystoreKeyStrategy strategy = new BasicKeystoreKeyStrategy();
        strategy.setKeystoreResource(ResourceHelper.of(new ClassPathResource("credentials/sealer.jks")));
        strategy.setKeyVersionResource(ResourceHelper.of(new ClassPathResource("credentials/sealer.kver")));
        strategy.setKeystorePassword("password");
        strategy.setKeyAlias("secret");
        strategy.setKeyPassword("password");
        strategy.initialize();
        final DataSealer dataSealer = new DataSealer();
        dataSealer.setKeyStrategy(strategy);
        dataSealer.setRandom(SecureRandom.getInstance("SHA1PRNG"));
        dataSealer.initialize();
        return dataSealer;
    }

    @Test
    public void testApproved() throws IOException, ParseException {
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        DeviceStateObject state = deviceCodesCache.getDeviceState("DC123456");
        Assert.assertEquals(DeviceStateObject.State.APPROVED, state.getState());
        Assert.assertNotNull(state.getAccessToken());
        Assert.assertNotNull(state.getExpiresAt());
    }

    @Test
    public void testDenied() throws IOException, ParseException {
        deviceUserAuthenticationContext.setUserApproved(false);
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        DeviceStateObject state = deviceCodesCache.getDeviceState("DC123456");
        Assert.assertEquals(DeviceStateObject.State.DENIED, state.getState());
        Assert.assertNull(state.getAccessToken());
        Assert.assertNull(state.getExpiresAt());
    }

    @Test
    public void testFailNoUserCode() throws IOException, ParseException {
        profileRequestCtx.getInboundMessageContext().addSubcontext(new DeviceUserAuthenticationContext(), true);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testFailNoDeviceCodeForUserCode() throws IOException, ParseException {
        deviceUserAuthenticationContext.setUserCode("UC123456_NOMATCH");
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MESSAGE);
    }

    @Test
    public void testFailNoRpCtx() throws IOException, ParseException {
        profileRequestCtx.removeSubcontext(RelyingPartyContext.class);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), IdPEventIds.INVALID_RELYING_PARTY_CTX);
    }

    @Test
    public void testFailNoProfileConfig() throws IOException, ParseException {
        profileRequestCtx.addSubcontext(new RelyingPartyContext(), true);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), IdPEventIds.INVALID_RELYING_PARTY_CTX);
    }

    @Test
    public void testFailNoSubjectCtx() throws IOException, ParseException {
        profileRequestCtx.removeSubcontext(SubjectContext.class);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_PROFILE_CTX);
    }

}