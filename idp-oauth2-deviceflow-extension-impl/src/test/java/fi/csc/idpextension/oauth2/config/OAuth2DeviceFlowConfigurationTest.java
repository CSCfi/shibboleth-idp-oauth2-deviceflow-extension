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

package fi.csc.idpextension.oauth2.config;

import java.time.Duration;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

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
        conf.setPollingInterval(Duration.ofSeconds(10));
        conf.setDeviceCodeLifetime(Duration.ofSeconds(11));
        conf.setDeviceCodeLength(20);
        conf.setUserCodeLength(10);
        Assert.assertEquals(Duration.ofSeconds(10), conf.getPollingInterval(null));
        Assert.assertEquals(Duration.ofSeconds(11), conf.getDeviceCodeLifetime(null));
        Assert.assertEquals((int) 20, (int) conf.getDeviceCodeLength(null));
        Assert.assertEquals((int) 10, (int) conf.getUserCodeLength(null));

    }

}