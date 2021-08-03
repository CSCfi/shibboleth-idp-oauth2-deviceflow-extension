/*
 * Copyright (c) 2019-2021 CSC- IT Center for Science, www.csc.fi
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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import java.util.function.Function;

import net.shibboleth.idp.plugin.oidc.op.config.OIDCCoreProtocolConfiguration;
import net.shibboleth.utilities.java.support.annotation.constraint.NonNegative;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.logic.FunctionSupport;

/**
 * Profile configuration for the OAuth2 Device Flow. Extending {@link OIDCCoreProtocolConfiguration} as we do not have
 * OAuth2CoreProtocolConfiguration (thus we inherit some undesired properties).
 */
public class OAuth2DeviceFlowConfiguration extends OIDCCoreProtocolConfiguration {

    /** OAuth2 Token Revocation URI. */
    public static final String PROTOCOL_URI = "https://oauth.net/2/device-flow/";

    /** ID for this profile configuration. */
    public static final String PROFILE_ID = "http://csc.fi/ns/profiles/oauth2/device";

    /** Lookup function to supply length of device code. */
    @Nullable
    private Function<ProfileRequestContext, Integer> deviceCodeLengthLookupStrategy;

    /** Lookup function to supply length of User Code. */
    @Nonnull
    private Function<ProfileRequestContext, Integer> userCodeLengthLookupStrategy;

    /** Lookup function to supply polling interval in seconds. */
    @Nonnull
    private Function<ProfileRequestContext, Duration> pollingIntervalLookupStrategy;

    /** Lookup function to supply lifetime of device code. */
    @Nonnull
    private Function<ProfileRequestContext, Duration> deviceCodeLifetimeLookupStrategy;

    /**
     * Constructor.
     */
    public OAuth2DeviceFlowConfiguration() {
        this(PROFILE_ID);
    }

    /**
     * Creates a new configuration instance.
     *
     * @param profileId Unique profile identifier.
     */
    public OAuth2DeviceFlowConfiguration(@Nonnull @NotEmpty final String profileId) {
        super(profileId);
        deviceCodeLengthLookupStrategy = FunctionSupport.constant(Integer.valueOf(16));
        userCodeLengthLookupStrategy = FunctionSupport.constant(Integer.valueOf(8));
        pollingIntervalLookupStrategy = FunctionSupport.constant(Duration.ofSeconds(5));
        deviceCodeLifetimeLookupStrategy = FunctionSupport.constant(Duration.ofMinutes(5));
    }

    /**
     * Get device code length
     * 
     * <p>
     * Defaults to minimum 16.
     * </p>
     * 
     * @param profileRequestContext profile request context
     * @return Device code length
     */
    @Nonnull
    @Positive
    public Integer getDeviceCodeLength(@Nullable final ProfileRequestContext profileRequestContext) {
        final Integer length = deviceCodeLengthLookupStrategy.apply(profileRequestContext);
        Constraint.isTrue(length != null && length > 15, "Device code length must be greater than or equal to 16");
        return length;
    }

    /**
     * Set the length of the device code.
     * 
     * @param length length of the device code.
     */
    public void setDeviceCodeLength(@Nonnull @Positive final Integer length) {
        Constraint.isTrue(length != null && length > 15, "Device code length must be greater than or equal to 16");
        deviceCodeLengthLookupStrategy = FunctionSupport.constant(length);
    }

    /**
     * Set a lookup strategy for the device code length.
     *
     * @param strategy lookup strategy
     */
    public void setDeviceCodeLengthLookupStrategy(@Nonnull final Function<ProfileRequestContext, Integer> strategy) {
        deviceCodeLengthLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /**
     * Get user code length
     * 
     * <p>
     * Defaults to 8. 6 is minimum.
     * </p>
     * 
     * @param profileRequestContext profile request context
     * @return user code length
     */
    @Nonnull
    @Positive
    public Integer getUserCodeLength(@Nullable final ProfileRequestContext profileRequestContext) {
        final Integer length = userCodeLengthLookupStrategy.apply(profileRequestContext);
        Constraint.isTrue(length != null && length > 5, "User code length must be greater than or equal to 6");
        return length;
    }

    /**
     * Set the length of the user code.
     * 
     * @param length length of the user code.
     */
    public void setUserCodeLength(@Nonnull @NonNegative final Integer length) {
        Constraint.isTrue(length != null && length > 5, "User code length must be greater than or equal to 6");
        userCodeLengthLookupStrategy = FunctionSupport.constant(length);
    }

    /**
     * Set a lookup strategy for the user code length.
     *
     * @param strategy lookup strategy
     */
    public void setUserCodeLengthLookupStrategy(@Nonnull final Function<ProfileRequestContext, Integer> strategy) {
        userCodeLengthLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /**
     * Get polling interval
     * 
     * <p>
     * Defaults to 5s.
     * </p>
     * 
     * @param profileRequestContext profile request context
     * @return polling interval
     */
    @Nonnull
    @NonNegative
    public Duration getPollingInterval(@Nullable final ProfileRequestContext profileRequestContext) {
        final Duration interval = pollingIntervalLookupStrategy.apply(profileRequestContext);
        Constraint.isTrue(interval != null && !interval.isNegative(),
                "Polling interval must be greater than or equal to 0s");
        return interval;
    }

    /**
     * Set the polling interval.
     * 
     * @param interval polling interval.
     */
    public void setPollingInterval(@Nonnull @NonNegative final Duration interval) {
        Constraint.isTrue(interval != null && !interval.isNegative(),
                "Polling interval must be greater than or equal to 0");
        pollingIntervalLookupStrategy = FunctionSupport.constant(interval);
    }

    /**
     * Set a lookup strategy for the polling interval.
     *
     * @param strategy lookup strategy
     */
    public void setPollingIntervalLookupStrategy(@Nonnull final Function<ProfileRequestContext, Duration> strategy) {
        pollingIntervalLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /**
     * Get device code lifetime.
     * 
     * <p>
     * Defaults to 5 minutes.
     * </p>
     * 
     * @param profileRequestContext profile request context
     * 
     * @return device code lifetime
     */
    @Positive
    @Nonnull
    public Duration getDeviceCodeLifetime(@Nullable final ProfileRequestContext profileRequestContext) {

        final Duration lifetime = deviceCodeLifetimeLookupStrategy.apply(profileRequestContext);

        Constraint.isTrue(lifetime != null && !lifetime.isZero() && !lifetime.isNegative(),
                "Device code lifetime must be greater than 0");
        return lifetime;
    }

    /**
     * Set the lifetime of an device code.
     * 
     * @param lifetime lifetime of an device code in milliseconds
     */
    public void setDeviceCodeLifetime(@Positive @Nonnull final Duration lifetime) {
        Constraint.isTrue(lifetime != null && !lifetime.isZero() && !lifetime.isNegative(),
                "Device code lifetime must be greater than 0");

        deviceCodeLifetimeLookupStrategy = FunctionSupport.constant(lifetime);
    }

    /**
     * Set a lookup strategy for the device code lifetime.
     *
     * @param strategy lookup strategy
     */
    public void setDeviceCodeLifetimeLookupStrategy(@Nonnull final Function<ProfileRequestContext, Duration> strategy) {
        deviceCodeLifetimeLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

}
