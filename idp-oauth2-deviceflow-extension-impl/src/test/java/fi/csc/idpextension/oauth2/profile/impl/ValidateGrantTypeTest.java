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

import java.util.HashSet;
import java.util.Set;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import fi.csc.idpextension.oauth2.messaging.impl.OAuth2DeviceTokenRequest;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link ValidateGrantType}.
 */
public class ValidateGrantTypeTest {

    protected RequestContext requestCtx;

    protected ProfileRequestContext profileRequestCtx;

    private ValidateGrantType action;

    private OIDCClientMetadata metaData;

    @BeforeMethod
    protected void setUp() throws Exception {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        action = new ValidateGrantType();
        action.initialize();
        profileRequestCtx.setInboundMessageContext(new MessageContext());
        OIDCMetadataContext oidcCtx =
                profileRequestCtx.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        metaData = new OIDCClientMetadata();
        Set<GrantType> grantTypes = new HashSet<GrantType>();
        grantTypes.add(GrantType.parse("refresh_token"));
        grantTypes.add(GrantType.parse(OAuth2DeviceTokenRequest.grantTypeValue));
        metaData.setGrantTypes(grantTypes);
        OIDCClientInformation information =
                new OIDCClientInformation(new ClientID("test"), null, metaData, null, null, null);
        oidcCtx.setClientInformation(information);

    }

    @Test
    public void testSuccess() {
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
    }

    @Test
    public void testFailNotRegistered() throws ParseException {
        Set<GrantType> grantTypes = new HashSet<GrantType>();
        grantTypes.add(GrantType.parse("refresh_token"));
        metaData.setGrantTypes(grantTypes);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), OidcEventIds.INVALID_GRANT_TYPE);
    }

    @Test
    public void testSuccessSetValue() throws ParseException, ComponentInitializationException {
        action = new ValidateGrantType();
        action.setExpectedGrantType("refresh_token");
        action.initialize();
        Set<GrantType> grantTypes = new HashSet<GrantType>();
        grantTypes.add(GrantType.parse("refresh_token"));
        metaData.setGrantTypes(grantTypes);
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
    }

    @Test
    public void testNoInboundMsgCtx() throws ParseException {
        profileRequestCtx.setInboundMessageContext(null);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_PROFILE_CTX);
    }

    @Test
    public void testNoMetadataCtx() throws ParseException {
        profileRequestCtx.getInboundMessageContext().removeSubcontext(OIDCMetadataContext.class);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MSG_CTX);
    }
}