/*
 * Copyright (c) 2024 CSC- IT Center for Science, www.csc.fi
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

package fi.csc.shibboleth.plugin.oauth2.config.impl;

import java.time.Duration;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import fi.csc.shibboleth.plugin.oauth2.config.OAuth2DeviceGrantConfiguration;
import net.shibboleth.oidc.profile.config.impl.AbstractOIDCSSOConfiguration;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.Positive;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.logic.FunctionSupport;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * Default profile configuration for the OAuth2 Device Grant.
 */
public class DefaultOAuth2DeviceGrantConfiguration extends AbstractOIDCSSOConfiguration
        implements OAuth2DeviceGrantConfiguration {

    /** OAuth2 Device Grant profile counter name. */
    @Nonnull @NotEmpty public static final String PROFILE_COUNTER = "net.shibboleth.idp.profiles.oauth2.devicegrant";

    /** Lookup function to supply device code lifetime. */
    @Nonnull
    private Function<ProfileRequestContext, Duration> deviceCodeLifetimeLookupStrategy;

    /** Lookup function to supply device code length. */
    @Nonnull
    private Function<ProfileRequestContext, Integer> deviceCodeLengthLookupStrategy;

    /** Lookup function to supply user code length. */
    @Nonnull
    private Function<ProfileRequestContext, Integer> userCodeLengthLookupStrategy;

    /** Lookup function to supply polling interval. */
    @Nonnull
    private Function<ProfileRequestContext, Duration> pollingIntervalLookupStrategy;
    
    /** Lookup function to supply verification URI. */
    @Nonnull private Function<ProfileRequestContext, String> verificationURILookupStrategy;

    /**
     * Constructor.
     */
    public DefaultOAuth2DeviceGrantConfiguration() {
        this(OAuth2DeviceGrantConfiguration.PROFILE_ID);
    }

    /**
     * Creates a new configuration instance.
     *
     * @param profileId unique profile identifier
     */
    public DefaultOAuth2DeviceGrantConfiguration(@Nonnull @NotEmpty final String profileId) {
        super(profileId);
        deviceCodeLifetimeLookupStrategy = FunctionSupport.constant(Duration.ofMinutes(10));
        deviceCodeLengthLookupStrategy = FunctionSupport.constant(Integer.valueOf(40));
        userCodeLengthLookupStrategy = FunctionSupport.constant(Integer.valueOf(8));
        pollingIntervalLookupStrategy = FunctionSupport.constant(Duration.ofSeconds(5));
        verificationURILookupStrategy = FunctionSupport.constant(null);
    }

    @Override
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
     * @param lifetime lifetime of an device code
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
    public void setDeviceCodeLifetimeLookupStrategy(
            @Nullable final Function<ProfileRequestContext, Duration> strategy) {
        deviceCodeLifetimeLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    @Override
    @Positive
    @Nonnull
    public Integer getDeviceCodeLength(@Nullable final ProfileRequestContext profileRequestContext) {
        final Integer codeLength = deviceCodeLengthLookupStrategy.apply(profileRequestContext);

        Constraint.isTrue(codeLength != null && codeLength >= 32 && codeLength <= 64,
                "Device code length must be from 32 to 64");
        return codeLength;
    }

    /**
     * Set the device code length.
     * 
     * @param codeLength length of the device code.
     */
    public void setDeviceCodeLength(@Positive @Nonnull final Integer codeLength) {
        Constraint.isTrue(codeLength != null && codeLength >= 32 && codeLength <= 64,
                "Device code length must be from 32 to 64");

        deviceCodeLengthLookupStrategy = FunctionSupport.constant(codeLength);
    }

    /**
     * Set a lookup strategy for the device code length.
     *
     * @param strategy lookup strategy
     */
    public void setDeviceCodeLengthLookupStrategy(@Nullable final Function<ProfileRequestContext, Integer> strategy) {
        deviceCodeLengthLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    @Override
    @Positive
    @Nonnull
    public Integer getUserCodeLength(@Nullable final ProfileRequestContext profileRequestContext) {
        final Integer codeLength = userCodeLengthLookupStrategy.apply(profileRequestContext);

        Constraint.isTrue(codeLength != null && codeLength > 5, "User code length must be at least 6");
        return codeLength;
    }

    /**
     * Set the user code length.
     * 
     * @param codeLength length of the user code.
     */
    public void setUserCodeLength(@Positive @Nonnull final Integer codeLength) {
        Constraint.isTrue(codeLength != null && codeLength > 5, "User code length must be at least 6");

        userCodeLengthLookupStrategy = FunctionSupport.constant(codeLength);
    }

    /**
     * Set a lookup strategy for the user code length.
     *
     * @param strategy lookup strategy
     */
    public void setUserCodeLengthLookupStrategy(@Nullable final Function<ProfileRequestContext, Integer> strategy) {
        userCodeLengthLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    @Override
    @Positive
    @Nonnull
    public Duration getPollingInterval(@Nullable final ProfileRequestContext profileRequestContext) {
        final Duration interval = pollingIntervalLookupStrategy.apply(profileRequestContext);

        Constraint.isTrue(interval != null && !interval.isZero() && !interval.isNegative(),
                "Polling interval must be greater than 0");
        return interval;
    }

    /**
     * Set the polling interval.
     * 
     * @param interval polling interval
     */
    public void setPollingInterval(@Positive @Nonnull final Duration interval) {
        Constraint.isTrue(interval != null && !interval.isZero() && !interval.isNegative(),
                "Polling interval must be greater than 0");

        pollingIntervalLookupStrategy = FunctionSupport.constant(interval);
    }

    /**
     * Set a lookup strategy for polling interval.
     *
     * @param strategy lookup strategy
     */
    public void setPollingIntervalLookupStrategy(@Nullable final Function<ProfileRequestContext, Duration> strategy) {
        pollingIntervalLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable @NotEmpty public String getVerificationURI(@Nullable final ProfileRequestContext profileRequestContext) {
        return verificationURILookupStrategy.apply(profileRequestContext);
    }

    /**
     * Set the verification URI.
     *
     * @param uri verification URI
     */
    public void setVerificationURI(@Nullable @NotEmpty final String uri) {
        verificationURILookupStrategy = FunctionSupport.constant(StringSupport.trimOrNull(uri));
    }

    /**
     * Set a lookup strategy for the verification URI.
     *
     * @param strategy lookup strategy
     */
    public void setVerificationURILookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        verificationURILookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

}
