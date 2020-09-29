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

package fi.csc.idpextension.oauth2.profile.context.navigate;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import fi.csc.idpextension.oauth2.messaging.context.DeviceUserAuthenticationContext;
import org.opensaml.messaging.context.MessageContext;
import org.testng.Assert;

/**
 * Unit tests for {@link DeviceUserApprovalLookupFunction}.
 */
public class DeviceUserApprovalLookupFunctionTest {

    private DeviceUserApprovalLookupFunction lookup;

    private MessageContext msgCtx;

    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new DeviceUserApprovalLookupFunction();
        msgCtx = new MessageContext();
        ((DeviceUserAuthenticationContext) msgCtx.addSubcontext(new DeviceUserAuthenticationContext()))
                .setUserApproved(true);
    }

    @Test
    public void lookupApproved() {
        Assert.assertEquals(lookup.apply(msgCtx), Boolean.TRUE);
    }

    @Test
    public void lookupDenied() {
        ((DeviceUserAuthenticationContext) msgCtx.getSubcontext(DeviceUserAuthenticationContext.class))
                .setUserApproved(false);
        Assert.assertEquals(lookup.apply(msgCtx), Boolean.FALSE);
    }

    @Test
    public void lookupFailNoAuthContext() {
        msgCtx.removeSubcontext(DeviceUserAuthenticationContext.class);
        Assert.assertFalse(lookup.apply(msgCtx));
    }

    @Test
    public void lookupFailNoMessageContext() {
        Assert.assertFalse(lookup.apply(null));
    }

}