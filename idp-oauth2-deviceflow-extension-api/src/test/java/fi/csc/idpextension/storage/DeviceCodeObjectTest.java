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

package fi.csc.idpextension.storage;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

public class DeviceCodeObjectTest {

    private DeviceCodeObject deviceCodeObject;

    @Test
    public void testConstructorAndSerialization() {
        deviceCodeObject = new DeviceCodeObject("deviceCode_XYZ", new ClientID("clientID_XYZ"), new Scope("scope_XYZ"));
        Assert.assertEquals(deviceCodeObject.getDeviceCode(), "deviceCode_XYZ");
        Assert.assertEquals(deviceCodeObject.getClientID().getValue(), "clientID_XYZ");
        Assert.assertTrue(deviceCodeObject.getScope().contains("scope_XYZ"));
        DeviceCodeObject newDeviceCodeObject = DeviceCodeObject.fromJSONObject(deviceCodeObject.toJSONObject());
        Assert.assertEquals(newDeviceCodeObject.getDeviceCode(), "deviceCode_XYZ");
        Assert.assertEquals(newDeviceCodeObject.getClientID().getValue(), "clientID_XYZ");
        Assert.assertTrue(newDeviceCodeObject.getScope().contains("scope_XYZ"));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorNullArgument() {
        new DeviceCodeObject(null, new ClientID("clientID_XYZ"), new Scope("scope_XYZ"));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorNullArgument2() {
        new DeviceCodeObject("deviceCode_XYZ", null, new Scope("scope_XYZ"));
    }

    @Test
    public void testConstructorNullArgument3() {
        deviceCodeObject = new DeviceCodeObject("deviceCode_XYZ", new ClientID("clientID_XYZ"), null);
        Assert.assertNull(deviceCodeObject.getScope());
    }
}
