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

import net.minidev.json.JSONObject;

/** Class wraps device state information for serialization. */
public class DeviceStateObject {

    /**
     * PENDING - User has not yet taken action. APPROVED - User approved the request. DENIED - User has denied the
     * request.
     */
    public enum State {
        /** User has not yet taken action. */
        PENDING,
        /** User approved the request. */
        APPROVED,
        /** User denied the request. */
        DENIED
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

    /** Client ID the device code was issued to. */
    @Nullable
    private String clientId;

    /** Polling interval in milliseconds. */
    @Nullable
    private Long interval;

    /** Time of the last token request, from EPOCH in milliseconds. */
    @Nullable
    private Long lastPoll;

    /**
     * Constructor.
     * 
     * @param state State of the request, PENDING, APPROVED or DENIED.
     * @param accessToken Access Token for APPROVED requests.
     * @param expiresAt Expires At of the Access Token for APPROVED requests. EPOCH in milliseconds.
     */
    public DeviceStateObject(@Nonnull final State state, @Nullable final String accessToken,
            @Nullable final Long expiresAt) {
        this(state, accessToken, expiresAt, null, null, null);
    }

    // Checkstyle: ParameterNumber OFF
    /**
     * Constructor.
     * 
     * @param state State of the request, PENDING, APPROVED or DENIED.
     * @param accessToken Access Token for APPROVED requests.
     * @param expiresAt Expires At of the Access Token for APPROVED requests. EPOCH in milliseconds.
     * @param clientId Client ID the device code was issued to.
     * @param interval Polling interval in milliseconds.
     * @param lastPoll Time of the last token request. EPOCH in milliseconds.
     */
    public DeviceStateObject(@Nonnull final State state, @Nullable final String accessToken,
            @Nullable final Long expiresAt, @Nullable final String clientId, @Nullable final Long interval,
            @Nullable final Long lastPoll) {
        if (state == null || accessToken != null && expiresAt == null) {
            throw new IllegalArgumentException(
                    "state must not be null. If access token is not null expires at cannot be null either");
        }
        if (state == State.APPROVED && accessToken == null) {
            throw new IllegalArgumentException("For approved state access token must be set");
        }
        this.state = state;
        this.accessToken = accessToken;
        this.expiresAt = expiresAt;
        this.clientId = clientId;
        this.interval = interval;
        this.lastPoll = lastPoll;
    }
    // Checkstyle: ParameterNumber ON

    /**
     * Constructor.
     * 
     * @param state State of the request, PENDING or DENIED.
     */
    public DeviceStateObject(final State state) {
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
     * Get Client ID the device code was issued to.
     * 
     * @return Client ID the device code was issued to.
     */
    @Nullable
    public String getClientId() {
        return clientId;
    }

    /**
     * Get polling interval in milliseconds.
     * 
     * @return polling interval in milliseconds.
     */
    @Nullable
    public Long getInterval() {
        return interval;
    }

    /**
     * Get time of the last token request, from EPOCH in milliseconds.
     * 
     * @return time of the last token request.
     */
    @Nullable
    public Long getLastPoll() {
        return lastPoll;
    }

    /**
     * Get a copy with a new state, keeping client ID, interval and last poll.
     * 
     * @param newState State of the request.
     * @param newAccessToken Access Token for APPROVED requests.
     * @param newExpiresAt Expires At of the Access Token for APPROVED requests. EPOCH in milliseconds.
     * @return copy with the new state.
     */
    @Nonnull
    public DeviceStateObject withState(@Nonnull final State newState, @Nullable final String newAccessToken,
            @Nullable final Long newExpiresAt) {
        return new DeviceStateObject(newState, newAccessToken, newExpiresAt, clientId, interval, lastPoll);
    }

    /**
     * Get a copy with a new last poll time and interval.
     * 
     * @param newLastPoll Time of the token request. EPOCH in milliseconds.
     * @param newInterval Polling interval in milliseconds.
     * @return copy with the new last poll time and interval.
     */
    @Nonnull
    public DeviceStateObject withPoll(final long newLastPoll, @Nullable final Long newInterval) {
        return new DeviceStateObject(state, accessToken, expiresAt, clientId, newInterval, newLastPoll);
    }

    /**
     * Wraps State, Access Token and Expires At to a JSON Object.
     * 
     * @return JSON Object representing the class information.
     */
    public JSONObject toJSONObject() {
        final JSONObject object = new JSONObject();
        object.put("state", state.name());
        if (accessToken != null) {
            object.put("access_token", accessToken);
            object.put("expires_in", expiresAt);

        }
        if (clientId != null) {
            object.put("client_id", clientId);
        }
        if (interval != null) {
            object.put("interval", interval);
        }
        if (lastPoll != null) {
            object.put("last_poll", lastPoll);
        }
        return object;
    }

    /**
     * Constructs a DeviceStateObject from JSON Object.
     * 
     * @param deviceStateObject JSON Object representing the class information.
     * @return DeviceStateObject constructed from JSON Object
     */
    public static DeviceStateObject fromJSONObject(final JSONObject deviceStateObject) {
        if (deviceStateObject == null) {
            throw new IllegalArgumentException("device state object must not be null");
        }
        return new DeviceStateObject(State.valueOf(deviceStateObject.getAsString("state")),
                deviceStateObject.getAsString("access_token"), getAsLong(deviceStateObject, "expires_in"),
                deviceStateObject.getAsString("client_id"), getAsLong(deviceStateObject, "interval"),
                getAsLong(deviceStateObject, "last_poll"));
    }

    /**
     * Get a number member of a JSON Object as Long.
     * 
     * @param object JSON Object
     * @param name member name
     * @return member value, null if not present
     */
    @Nullable
    private static Long getAsLong(@Nonnull final JSONObject object, @Nonnull final String name) {
        final Number value = object.getAsNumber(name);
        return value == null ? null : value.longValue();
    }

}
