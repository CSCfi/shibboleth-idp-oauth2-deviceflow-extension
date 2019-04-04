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

package fi.csc.idpextension.oauth2.messaging.error;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

public final class OAuth2DeviceError {

    /**
     * The authorization request is still pending as the end user hasn't yet completed the user interaction steps.
     */
    public static final ErrorObject AUTHORIZATION_PENDING = new ErrorObject("authorization_pending",
            "The authorization request is still pending as the end user hasn't yet completed the user interaction steps",
            HTTPResponse.SC_BAD_REQUEST);

    /**
     * The "device_code" has expired and the device authorization session has concluded.
     */
    public static final ErrorObject EXPIRED_TOKEN = new ErrorObject("expired_token",
            "The device code has expired and the device authorization sessio has concluded",
            HTTPResponse.SC_BAD_REQUEST);

}
