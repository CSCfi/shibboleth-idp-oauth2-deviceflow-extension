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

package fi.csc.shibboleth.plugin.oauth2.devicegrant.messaging.context;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.shared.logic.ConstraintViolationException;


/** Unit tests for {@link DeviceUserAuthenticationContext}. */
public class DeviceUserAuthenticationContextTest {

    private DeviceUserAuthenticationContext deviceUserAuthenticationContext;

    @BeforeMethod
    public void setup() {
        deviceUserAuthenticationContext = new DeviceUserAuthenticationContext();
    }

    @Test
    public void testInitialState() {
        Assert.assertNull(deviceUserAuthenticationContext.getUserCode());
        Assert.assertFalse(deviceUserAuthenticationContext.isUserApproved());
    }

    @Test
    public void testSetters() {
        deviceUserAuthenticationContext.setUserCode("user_code");
        deviceUserAuthenticationContext.setUserApproved(true);
        Assert.assertEquals("user_code", deviceUserAuthenticationContext.getUserCode());
        Assert.assertTrue(deviceUserAuthenticationContext.isUserApproved());
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNullUserCode() {
        deviceUserAuthenticationContext.setUserCode(null);
    }

}
