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

package fi.csc.idpextension.storage;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.minidev.json.JSONObject;

/** Class wraps device state information for serialization. */
public class DeviceStateObject {

    /**
     * PENDING - User has not yet taken action. APPROVED - User approved the request. DENIED - User has denied the
     * request.
     */
    public enum State {
        PENDING, APPROVED, DENIED
    }

    /** State of the Device flow request. */
    @Nonnull
    private State state;

    /** Access Token, only for APPROVED requests. */
    @Nullable
    private String accessToken;

    /** Access Token Expires At, from EPOCH in milliseconds. */
    @Nullable
    private Long expiresAt;

    /**
     * Constructor.
     * 
     * @param state State of the request, PENDING, APPROVED or DENIED.
     * @param accessToken Access Token for APPROVED requests.
     * @param expiresAt Expires At of the Access Token for APPROVED requests. EPOCH in milliseconds.
     */
    public DeviceStateObject(@Nonnull State state, @Nullable String accessToken, @Nullable Long expiresAt) {
        if (state == null || (accessToken != null && expiresAt == null)) {
            throw new IllegalArgumentException(
                    "state must not be null. If access token is not null expires at cannot be null either");
        }
        if (state == State.APPROVED && accessToken == null) {
            throw new IllegalArgumentException("For approved state access token must be set");
        }
        this.state = state;
        this.accessToken = accessToken;
        this.expiresAt = expiresAt;
    }

    /**
     * Constructor.
     * 
     * @param state State of the request, PENDING or DENIED.
     */
    public DeviceStateObject(State state) {
        this(state, null, null);
    }

    /**
     * Constructor. Creates object in PENDING state.
     */
    public DeviceStateObject() {
        this(State.PENDING, null, null);
    }

    /**
     * Get State of the object. PENDING, APPROVED or DENIED.
     * 
     * @return State of the object.
     */
    @Nonnull
    public State getState() {
        return state;
    }

    /**
     * Get Access Token, only for APPROVED requests.
     * 
     * @return Access Token, only for APPROVED requests.
     */
    @Nullable
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * Get Access Token Expires At, from EPOCH in milliseconds.
     * 
     * @return Expires At, only for APPROVED requests.
     */
    @Nullable
    public Long getExpiresAt() {
        return expiresAt;
    }

    /**
     * Wraps State, Access Token and Expires At to a JSON Object.
     * 
     * @return JSON Object representing the class information.
     */
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put("state", state.name());
        if (accessToken != null) {
            object.put("access_token", accessToken);
            object.put("expires_in", expiresAt);

        }
        return object;
    }

    /**
     * Constructs a DeviceStateObject from JSON Object.
     * 
     * @param deviceStateObject JSON Object representing the class information.
     * @return DeviceStateObject constructed from JSON Object
     */
    public static DeviceStateObject fromJSONObject(JSONObject deviceStateObject) {
        if (deviceStateObject == null) {
            throw new IllegalArgumentException("device state object must not be null");
        }
        return new DeviceStateObject(State.valueOf(deviceStateObject.getAsString("state")),
                deviceStateObject.getAsString("access_token"), deviceStateObject.getAsNumber("expires_in") == null
                        ? null : deviceStateObject.getAsNumber("expires_in").longValue());
    }

}
