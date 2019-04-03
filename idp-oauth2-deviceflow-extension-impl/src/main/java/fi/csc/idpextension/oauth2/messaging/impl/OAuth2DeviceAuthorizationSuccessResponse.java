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

package fi.csc.idpextension.oauth2.messaging.impl;

import java.net.URI;

import com.nimbusds.oauth2.sdk.SuccessResponse;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import net.minidev.json.JSONObject;

public class OAuth2DeviceAuthorizationSuccessResponse implements SuccessResponse {

    private final String deviceCode;

    private final String userCode;

    private final URI verificationURI;

    private final URI verificationURIComplete;

    private final Integer expiresIn;

    private final Integer interval;

    public OAuth2DeviceAuthorizationSuccessResponse(String deviceCode, String userCode, URI verificationURI,
            URI verificationURIComplete, Integer expiresIn, Integer interval) {
        if (deviceCode == null || userCode == null || verificationURI == null || expiresIn == null) {
            throw new IllegalArgumentException(
                    "device code, user code, verification uri and expiresIn must not be null");
        }
        this.deviceCode = deviceCode;
        this.userCode = userCode;
        this.verificationURI = verificationURI;
        this.verificationURIComplete = verificationURIComplete;
        this.expiresIn = expiresIn;
        this.interval = interval;
    }

    public OAuth2DeviceAuthorizationSuccessResponse(String deviceCode, String userCode, URI verificationURI,
            int expiresIn) {
        this(deviceCode, userCode, verificationURI, null, expiresIn, null);
    }

    public String getDeviceCode() {
        return deviceCode;
    }

    public String getUserCode() {
        return userCode;
    }

    public URI getVerificationURI() {
        return verificationURI;
    }

    public URI getVerificationURIComplete() {
        return verificationURIComplete;
    }

    public Integer getExpiresIn() {
        return expiresIn;
    }

    public Integer getInterval() {
        return interval;
    }

    @Override
    public boolean indicatesSuccess() {
        return true;
    }

    public JSONObject toJSONObject() {

        JSONObject content = new JSONObject();
        content.put("device_code", deviceCode);
        content.put("user_code", userCode);
        content.put("verification_uri", verificationURI.toString());
        if (verificationURIComplete != null) {
            content.put("verification_uri_complete", verificationURIComplete.toString());
        }
        content.put("expires_in", expiresIn.toString());
        if (interval != null) {
            content.put("interval", interval.toString());
        }
        return content;
    }

    @Override
    public HTTPResponse toHTTPResponse() {

        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");
        httpResponse.setContent(toJSONObject().toString());
        return httpResponse;
    }

}
