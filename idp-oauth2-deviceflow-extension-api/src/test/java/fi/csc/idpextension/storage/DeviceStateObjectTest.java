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

import fi.csc.idpextension.storage.DeviceStateObject.State;

public class DeviceStateObjectTest {

    private DeviceStateObject deviceStateObject;

    @Test
    public void testConstructorAndSerialization() {
        deviceStateObject = new DeviceStateObject(State.APPROVED, "accessToken_XYZ", 1000000L);
        Assert.assertEquals(deviceStateObject.getState(), State.APPROVED);
        Assert.assertEquals(deviceStateObject.getAccessToken(), "accessToken_XYZ");
        Assert.assertEquals(deviceStateObject.getExpiresAt(), (Long) 1000000L);
        DeviceStateObject newDeviceStateObject = DeviceStateObject.fromJSONObject(deviceStateObject.toJSONObject());
        Assert.assertEquals(newDeviceStateObject.getState(), State.APPROVED);
        Assert.assertEquals(newDeviceStateObject.getAccessToken(), "accessToken_XYZ");
        Assert.assertEquals(newDeviceStateObject.getExpiresAt(), (Long) 1000000L);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorNullArgument() {
        new DeviceStateObject(State.APPROVED, null, null);
    }

    @Test
    public void testDefaultConstructor() {
        deviceStateObject = new DeviceStateObject();
        Assert.assertEquals(deviceStateObject.getState(), State.PENDING);
        Assert.assertNull(deviceStateObject.getAccessToken());
        Assert.assertNull(deviceStateObject.getExpiresAt());
    }

}
