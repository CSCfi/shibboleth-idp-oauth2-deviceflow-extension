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

package fi.csc.idpextension.oauth2.config;

import java.security.Principal;
import java.util.Arrays;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.csc.idpextension.oauth2.config.OAuth2DeviceFlowConfiguration;
import junit.framework.Assert;
import net.shibboleth.idp.saml.authn.principal.AuthenticationMethodPrincipal;

/**
 * Tests for {@link OAuth2DeviceFlowConfiguration}.
 */
public class OAuth2DeviceFlowConfigurationTest {

    private OAuth2DeviceFlowConfiguration conf;

    @BeforeMethod
    protected void setUp() throws Exception {
        conf = new OAuth2DeviceFlowConfiguration();
    }

    @Test
    public void test() {
        Assert.assertEquals(OAuth2DeviceFlowConfiguration.PROFILE_ID, conf.getId());
        conf = new OAuth2DeviceFlowConfiguration("somethingelse");
        Assert.assertEquals("somethingelse", conf.getId());
    }

    @Test
    public void testSetters() {
        conf.setAccessTokenLifetime(5);
        Assert.assertEquals(5, conf.getAccessTokenLifetime());
        conf.setAuthenticationFlows(Arrays.asList("flow1", "flow2"));
        Assert.assertEquals(2, conf.getAuthenticationFlows().size());
        Assert.assertTrue(conf.getAuthenticationFlows().contains("flow1"));
        Assert.assertTrue(conf.getAuthenticationFlows().contains("flow2"));
        conf.setDefaultAuthenticationMethods(Arrays.asList((Principal) new AuthenticationMethodPrincipal("method1"),
                (Principal) new AuthenticationMethodPrincipal("method2")));
        Assert.assertEquals(2, conf.getDefaultAuthenticationMethods().size());
        Assert.assertTrue(conf.getDefaultAuthenticationMethods()
                .contains((Principal) new AuthenticationMethodPrincipal("method1")));
        Assert.assertTrue(conf.getDefaultAuthenticationMethods()
                .contains((Principal) new AuthenticationMethodPrincipal("method2")));
        conf.setDeviceCodeLength(5);
        Assert.assertEquals(5, conf.getDeviceCodeLength());
        conf.setDeviceCodeLifetime(6);
        Assert.assertEquals(6, conf.getDeviceCodeLifetime());
        conf.setUserCodeLength(7);
        Assert.assertEquals(7, conf.getUserCodeLength());
        conf.setPostAuthenticationFlows(Arrays.asList("pflow1", "pflow2"));
        Assert.assertEquals(2, conf.getPostAuthenticationFlows().size());
        Assert.assertTrue(conf.getPostAuthenticationFlows().contains("pflow1"));
        Assert.assertTrue(conf.getPostAuthenticationFlows().contains("pflow2"));
        conf.setNameIDFormatPrecedence(Arrays.asList("format1", "format2"));
        Assert.assertEquals(2, conf.getNameIDFormatPrecedence().size());
        Assert.assertTrue(conf.getNameIDFormatPrecedence().get(0).equals("format1"));
        Assert.assertTrue(conf.getNameIDFormatPrecedence().get(1).equals("format2"));
    }

}