/*
 * Copyright (c) 2024 CSC- IT Center for Science, www.csc.fi
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

package fi.csc.shibboleth.plugin.oauth2.profile.impl;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.impl.MemoryStorageService;
import org.opensaml.storage.impl.StorageServiceReplayCache;
import org.opensaml.storage.impl.StorageServiceRevocationCache;
import org.springframework.core.io.ClassPathResource;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.device.DeviceCode;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;
import com.nimbusds.oauth2.sdk.id.ClientID;

import fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.DeviceEventIds;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodeObject;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodesCache;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceStateObject;
import net.shibboleth.idp.plugin.oidc.op.messaging.context.OIDCAuthenticationResponseContext;
import net.shibboleth.idp.plugin.oidc.op.storage.RevocationCacheContexts;
import net.shibboleth.idp.plugin.oidc.op.token.support.AuthorizeCodeClaimsSet;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.idp.profile.testing.ActionTestingSupport;
import net.shibboleth.idp.profile.testing.RequestContextBuilder;
import net.shibboleth.oidc.profile.core.OidcEventIds;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.security.DataSealer;
import net.shibboleth.shared.security.impl.BasicKeystoreKeyStrategy;
import net.shibboleth.shared.security.impl.SecureRandomIdentifierGenerationStrategy;
import net.shibboleth.shared.spring.resource.ResourceHelper;

/**
 * Unit tests for {@link ValidateDeviceCodeGrant}.
 */
public class ValidateDeviceCodeGrantTest {

    private RequestContext requestCtx;

    private ProfileRequestContext profileRequestCtx;

    private ValidateDeviceCodeGrant action;

    private MemoryStorageService storageService;

    private DeviceCodesCache deviceCodesCache;

    private DataSealer dataSealer;

    private StorageServiceReplayCache replayCache;

    private StorageServiceRevocationCache revocationCache;

    @BeforeMethod
    protected void setUp() throws Exception {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        profileRequestCtx.setInboundMessageContext(new MessageContext());
        setGrant(new DeviceCodeGrant(new DeviceCode("DC123456")));
        profileRequestCtx.setOutboundMessageContext(new MessageContext());
        profileRequestCtx.getOutboundMessageContext().addSubcontext(new OIDCAuthenticationResponseContext());
        profileRequestCtx.ensureSubcontext(RelyingPartyContext.class).setRelyingPartyId("client_id");
        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.initialize();
        deviceCodesCache = new DeviceCodesCache();
        deviceCodesCache.setStorage(storageService);
        deviceCodesCache.initialize();
        deviceCodesCache.storeDeviceCode(new DeviceCodeObject("DC123456", new ClientID("client_id"), null, null),
                "UC123456", 100000, 5000L);
        replayCache = new StorageServiceReplayCache();
        replayCache.setStorage(storageService);
        replayCache.initialize();
        revocationCache = new StorageServiceRevocationCache();
        revocationCache.setId("revocationCache");
        revocationCache.setStorage(storageService);
        revocationCache.initialize();
        dataSealer = getDataSealer();
        action = newAction();
        action.initialize();
    }

    private ValidateDeviceCodeGrant newAction() {
        final ValidateDeviceCodeGrant validateAction = new ValidateDeviceCodeGrant(dataSealer);
        validateAction.setDeviceCodesCache(deviceCodesCache);
        validateAction.setReplayCache(replayCache);
        validateAction.setRevocationCache(revocationCache);
        return validateAction;
    }

    @AfterMethod
    protected void tearDown() {
        deviceCodesCache.destroy();
        storageService.destroy();
    }

    public DataSealer getDataSealer() throws ComponentInitializationException, NoSuchAlgorithmException {
        final BasicKeystoreKeyStrategy strategy = new BasicKeystoreKeyStrategy();
        strategy.setKeystoreResource(ResourceHelper.of(new ClassPathResource("credentials/sealer.jks")));
        strategy.setKeyVersionResource(ResourceHelper.of(new ClassPathResource("credentials/sealer.kver")));
        strategy.setKeystorePassword("password");
        strategy.setKeyAlias("secret");
        strategy.setKeyPassword("password");
        strategy.initialize();
        final DataSealer sealer = new DataSealer();
        sealer.setKeyStrategy(strategy);
        sealer.setRandom(SecureRandom.getInstance("SHA1PRNG"));
        sealer.initialize();
        return sealer;
    }

    private void setGrant(final AuthorizationGrant grant) throws Exception {
        profileRequestCtx.getInboundMessageContext().setMessage(
                new TokenRequest(new URI("https://op.example.org/token"), new ClientID("client_id"), grant));
    }

    private String approve(final String clientId, final Instant exp) throws Exception {
        final AuthorizeCodeClaimsSet claimsSet = new AuthorizeCodeClaimsSet.Builder()
                .setJWTID(new SecureRandomIdentifierGenerationStrategy())
                .setClientID(new ClientID(clientId))
                .setIssuer("issuer")
                .setPrincipal("principal")
                .setSubject("subject")
                .setIssuedAt(Instant.now())
                .setExpiresAt(exp)
                .setAuthenticationTime(Instant.now())
                .setScope(new Scope("openid"))
                .build();
        setState(DeviceStateObject.State.APPROVED, claimsSet.serialize(dataSealer), exp.toEpochMilli());
        return claimsSet.getID();
    }

    private void setState(final DeviceStateObject.State state, final String grant, final Long exp)
            throws Exception {
        deviceCodesCache.updateDeviceState("DC123456",
                deviceCodesCache.getDeviceState("DC123456").withState(state, grant, exp));
    }

    private OIDCAuthenticationResponseContext getResponseContext() {
        return profileRequestCtx.getOutboundMessageContext().getSubcontext(OIDCAuthenticationResponseContext.class);
    }

    @Test
    public void testApproved() throws Exception {
        approve("client_id", Instant.now().plusSeconds(100));
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertNotNull(getResponseContext().getAuthorizationGrantClaimsSet());
        Assert.assertEquals(getResponseContext().getAuthorizationGrantClaimsSet().getPrincipal(), "principal");
        Assert.assertNull(getResponseContext().getDpopProofJwkThumbprint());
    }

    @Test
    public void testReplay() throws Exception {
        final String jti = approve("client_id", Instant.now().plusSeconds(100));
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertFalse(revocationCache.isRevoked(RevocationCacheContexts.AUTHORIZATION_CODE, jti));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT);
        Assert.assertTrue(revocationCache.isRevoked(RevocationCacheContexts.AUTHORIZATION_CODE, jti));
    }

    @Test
    public void testRevocationCondition() throws Exception {
        action = newAction();
        action.setTokenRevocationCondition((prc, claims) -> true);
        action.initialize();
        approve("client_id", Instant.now().plusSeconds(100));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT);
        Assert.assertNull(getResponseContext().getAuthorizationGrantClaimsSet());
    }

    @Test
    public void testNoRevocationCache() {
        final ValidateDeviceCodeGrant validateAction = new ValidateDeviceCodeGrant(dataSealer);
        validateAction.setDeviceCodesCache(deviceCodesCache);
        validateAction.setReplayCache(replayCache);
        try {
            validateAction.initialize();
            Assert.fail("RevocationCache is required");
        } catch (final ComponentInitializationException e) {
        }
    }

    @Test
    public void testPending() throws Exception {
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.AUTHORIZATION_PENDING);
    }

    @Test
    public void testSlowDown() throws Exception {
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.AUTHORIZATION_PENDING);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.SLOW_DOWN);
        Assert.assertEquals(deviceCodesCache.getDeviceState("DC123456").getInterval(), Long.valueOf(10000));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.SLOW_DOWN);
        Assert.assertEquals(deviceCodesCache.getDeviceState("DC123456").getInterval(), Long.valueOf(15000));
    }

    @Test
    public void testPollAfterInterval() throws Exception {
        deviceCodesCache.storeDeviceCode(new DeviceCodeObject("DC_FAST", new ClientID("client_id"), null, null),
                "UC_FAST", 100000, 1L);
        setGrant(new DeviceCodeGrant(new DeviceCode("DC_FAST")));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.AUTHORIZATION_PENDING);
        Thread.sleep(10);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.AUTHORIZATION_PENDING);
    }

    @Test
    public void testPendingOtherClient() throws Exception {
        profileRequestCtx.getSubcontext(RelyingPartyContext.class).setRelyingPartyId("other_client");
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT);
    }

    @Test
    public void testDenied() throws Exception {
        setState(DeviceStateObject.State.DENIED, null, null);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.USER_DENIED);
    }

    @Test
    public void testDeniedOtherClient() throws Exception {
        setState(DeviceStateObject.State.DENIED, null, null);
        profileRequestCtx.getSubcontext(RelyingPartyContext.class).setRelyingPartyId("other_client");
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT);
    }

    @Test
    public void testUnknownDeviceCode() throws Exception {
        setGrant(new DeviceCodeGrant(new DeviceCode("DC_NOMATCH")));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.EXPIRED_TOKEN);
    }

    @Test
    public void testExpiredGrant() throws Exception {
        approve("client_id", Instant.now().minusSeconds(100));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), DeviceEventIds.EXPIRED_TOKEN);
    }

    @Test
    public void testOtherClient() throws Exception {
        approve("other_client", Instant.now().plusSeconds(100));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT);
    }

    @Test
    public void testInvalidSealedGrant() throws Exception {
        setState(DeviceStateObject.State.APPROVED, "not_sealed", 0L);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT);
    }

    @Test
    public void testNotDeviceCodeGrant() throws Exception {
        setGrant(new AuthorizationCodeGrant(new AuthorizationCode("code"), new URI("https://client.example.org")));
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT);
    }

    @Test
    public void testFailNoRpCtx() throws Exception {
        profileRequestCtx.removeSubcontext(RelyingPartyContext.class);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), IdPEventIds.INVALID_RELYING_PARTY_CTX);
    }

}
