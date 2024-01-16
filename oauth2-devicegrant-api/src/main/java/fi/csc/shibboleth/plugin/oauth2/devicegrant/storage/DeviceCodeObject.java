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

package fi.csc.shibboleth.plugin.oauth2.devicegrant.storage;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import net.minidev.json.JSONObject;

/** Class wraps device code information for serialization. */
public class DeviceCodeObject {

    /** Device Code. */
    @Nonnull
    private final String deviceCode;

    /** Client ID of the relying party. */
    @Nonnull
    private final ClientID clientID;

    /** Scope of the request. */
    @Nullable
    private final Scope scope;

    /**
     * Constructor.
     * 
     * @param deviceCode Device Code
     * @param clientID Client ID of the relying party
     * @param scope Scope of the request
     */
    public DeviceCodeObject(@Nonnull String deviceCode, @Nonnull ClientID clientID, @Nullable Scope scope) {
        if (deviceCode == null || clientID == null) {
            throw new IllegalArgumentException("device code and client id must not be null");
        }
        this.deviceCode = deviceCode;
        this.clientID = clientID;
        this.scope = scope;
    }

    /**
     * Get Device Code.
     * 
     * @return Device Code
     */
    @Nonnull
    public String getDeviceCode() {
        return deviceCode;
    }

    /**
     * Get Client ID of the relying party.
     * 
     * @return Client ID of the relying party
     */
    @Nonnull
    public ClientID getClientID() {
        return clientID;
    }

    /**
     * Get scope of the request.
     * 
     * @return scope of the request
     */
    @Nullable
    public Scope getScope() {
        return scope;
    }

    /**
     * Wraps Device Code, Client ID and scope to a JSON Object.
     * 
     * @return JSON Object representing the class information.
     */
    @Nonnull
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put("device_code", deviceCode);
        object.put("client_id", clientID.getValue());
        if (scope != null) {
            object.put("scope", scope.toString());
        }
        return object;
    }

    /**
     * Constructs a DeviceCodeObject from JSON Object.
     * 
     * @param deviceCodeObject JSON Object representing the class information.
     * @return DeviceCodeObject constructed from JSON Object
     */
    public static DeviceCodeObject fromJSONObject(JSONObject deviceCodeObject) {
        if (deviceCodeObject == null) {
            throw new IllegalArgumentException("device code object must not be null");
        }
        return new DeviceCodeObject(deviceCodeObject.getAsString("device_code"),
                new ClientID(deviceCodeObject.getAsString("client_id")),
                Scope.parse(deviceCodeObject.getAsString("scope")));
    }

}
