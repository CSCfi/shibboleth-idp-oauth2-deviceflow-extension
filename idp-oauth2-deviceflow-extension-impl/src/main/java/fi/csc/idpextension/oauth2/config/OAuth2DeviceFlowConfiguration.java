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

package fi.csc.idpextension.oauth2.config;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.config.AbstractOIDCClientAuthenticableProfileConfiguration;
import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Function;
import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

import net.shibboleth.idp.authn.config.AuthenticationProfileConfiguration;
import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Profile configuration for the OAuth2 Device Flow.
 */
public class OAuth2DeviceFlowConfiguration extends AbstractOIDCClientAuthenticableProfileConfiguration
        implements AuthenticationProfileConfiguration {

    /** OAuth2 Token Revocation URI. */
    public static final String PROTOCOL_URI = "https://oauth.net/2/device-flow/";

    /** ID for this profile configuration. */
    public static final String PROFILE_ID = "http://csc.fi/ns/profiles/oauth2/device";

    /** Selects, and limits, the authentication contexts to use for requests. */
    @Nonnull
    @NonnullElements
    private List<Principal> defaultAuthenticationContexts;

    /** Filters the usable authentication flows. */
    @Nonnull
    @NonnullElements
    private Set<String> authenticationFlows;

    /** Enables post-authentication interceptor flows. */
    @Nonnull
    @NonnullElements
    private List<String> postAuthenticationFlows;

    /** Precedence of name identifier formats to use for requests. */
    @Nonnull
    @NonnullElements
    private List<String> nameIDFormatPrecedence;

    /** Lookup function to supply {@link #accessTokenLifetime} property. */
    @SuppressWarnings("rawtypes")
    @Nullable
    private Function<ProfileRequestContext, Long> accessTokenLifetimeLookupStrategy;

    /** Lifetime of an access token in milliseconds. Default value: 5 minutes */
    @Positive
    @Duration
    private long accessTokenLifetime;

    /** Lookup function to supply {@link #deviceCodeLength} property. */
    @SuppressWarnings("rawtypes")
    @Nullable
    private Function<ProfileRequestContext, Long> deviceCodeLengthLookupStrategy;

    /** Length of the device code. Default is 16. */
    @Positive
    private long deviceCodeLength;

    /** Lookup function to supply {@link #userCodeLength} property. */
    @SuppressWarnings("rawtypes")
    @Nullable
    private Function<ProfileRequestContext, Long> userCodeLengthLookupStrategy;

    /** Length of the user code.Default is 6. */
    @Positive
    private long userCodeLength;

    /** Lookup function to supply {@link #deviceCodeLifetime} property. */
    @SuppressWarnings("rawtypes")
    @Nullable
    private Function<ProfileRequestContext, Long> deviceCodeLifetimeLookupStrategy;

    /** Lifetime of device/user codes. */
    @Positive
    @Duration
    private long deviceCodeLifetime;

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
        defaultAuthenticationContexts = Collections.emptyList();
        authenticationFlows = Collections.emptySet();
        postAuthenticationFlows = Collections.emptyList();
        nameIDFormatPrecedence = Collections.emptyList();
        accessTokenLifetime = 5 * 60 * 1000;
        deviceCodeLifetime = 5 * 60 * 1000;
        deviceCodeLength = 16;
        userCodeLength = 6;
    }

    @Override
    public List<Principal> getDefaultAuthenticationMethods() {
        return ImmutableList.<Principal> copyOf(defaultAuthenticationContexts);
    }

    /**
     * Set the default authentication contexts to use, expressed as custom principals.
     * 
     * @param contexts default authentication contexts to use
     */
    public void setDefaultAuthenticationMethods(@Nonnull @NonnullElements final List<Principal> contexts) {
        Constraint.isNotNull(contexts, "List of contexts cannot be null");

        defaultAuthenticationContexts = new ArrayList<>(Collections2.filter(contexts, Predicates.notNull()));
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public Set<String> getAuthenticationFlows() {
        return ImmutableSet.copyOf(authenticationFlows);
    }

    /**
     * Set the authentication flows to use.
     * 
     * @param flows flow identifiers to use
     */
    public void setAuthenticationFlows(@Nonnull @NonnullElements final Collection<String> flows) {
        Constraint.isNotNull(flows, "Collection of flows cannot be null");

        authenticationFlows = new HashSet<>(StringSupport.normalizeStringCollection(flows));
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<String> getPostAuthenticationFlows() {
        return postAuthenticationFlows;
    }

    /**
     * Set the ordered collection of post-authentication interceptor flows to enable.
     * 
     * @param flows flow identifiers to enable
     */
    public void setPostAuthenticationFlows(@Nonnull @NonnullElements final Collection<String> flows) {
        Constraint.isNotNull(flows, "Collection of flows cannot be null");

        postAuthenticationFlows = new ArrayList<>(StringSupport.normalizeStringCollection(flows));
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<String> getNameIDFormatPrecedence() {
        return ImmutableList.copyOf(nameIDFormatPrecedence);
    }

    /**
     * Set the name identifier formats to use.
     * 
     * @param formats name identifier formats to use
     */
    public void setNameIDFormatPrecedence(@Nonnull @NonnullElements final List<String> formats) {
        Constraint.isNotNull(formats, "List of formats cannot be null");

        nameIDFormatPrecedence = new ArrayList<>(StringSupport.normalizeStringCollection(formats));
    }

    /**
     * Set a lookup strategy for the {@link #accessTokenLifetime} property.
     *
     * @param strategy lookup strategy
     */
    public void setAccessTokenLifetimeLookupStrategy(
            @SuppressWarnings("rawtypes") @Nullable final Function<ProfileRequestContext, Long> strategy) {
        accessTokenLifetimeLookupStrategy = strategy;
    }

    /**
     * Set the lifetime of an access token.
     * 
     * @param lifetime lifetime of an access token in milliseconds
     */
    @Duration
    public void setAccessTokenLifetime(@Positive @Duration final long lifetime) {
        accessTokenLifetime = Constraint.isGreaterThan(0, lifetime, "access token lifetime must be greater than 0");
    }

    /**
     * Get access token lifetime.
     * 
     * @return access token lifetime is ms.
     */
    @Positive
    @Duration
    public long getAccessTokenLifetime() {
        return Constraint.isGreaterThan(0, getIndirectProperty(accessTokenLifetimeLookupStrategy, accessTokenLifetime),
                "access token lifetime must be greater than 0");
    }

    /**
     * Set a lookup strategy for the {@link #deviceCodeLength} property.
     *
     * @param strategy lookup strategy
     */
    public void setDeviceCodeLengthLookupStrategy(
            @SuppressWarnings("rawtypes") @Nullable final Function<ProfileRequestContext, Long> strategy) {
        deviceCodeLengthLookupStrategy = strategy;
    }

    /**
     * Set the length of the device code.
     * 
     * @param length length of the device code.
     */
    @Positive
    public void setDeviceCodeLength(@Positive final long length) {
        deviceCodeLength = Constraint.isGreaterThan(0, length, "device code length must be greater than 0");
    }

    /**
     * Get device code length.
     * 
     * @return device code length.
     */
    @Positive
    public long getDeviceCodeLength() {
        return Constraint.isGreaterThan(0, getIndirectProperty(deviceCodeLengthLookupStrategy, deviceCodeLength),
                "device code length must be greater than 0");
    }

    /**
     * Set a lookup strategy for the {@link #userCodeLength} property.
     *
     * @param strategy lookup strategy
     */
    public void setUserCodeLengthLookupStrategy(
            @SuppressWarnings("rawtypes") @Nullable final Function<ProfileRequestContext, Long> strategy) {
        userCodeLengthLookupStrategy = strategy;
    }

    /**
     * Set the length of the user code.
     * 
     * @param length length of the user code.
     */
    @Positive
    public void setUserCodeLength(@Positive final long length) {
        userCodeLength = Constraint.isGreaterThan(0, length, "user code length must be greater than 0");
    }

    /**
     * Get device code length.
     * 
     * @return device code length.
     */
    @Positive
    public long getUserCodeLength() {
        return Constraint.isGreaterThan(0, getIndirectProperty(userCodeLengthLookupStrategy, userCodeLength),
                "user code length must be greater than 0");
    }

    /**
     * Set a lookup strategy for the {@link #deviceCodeLifetime} property.
     *
     * @param strategy lookup strategy
     */
    public void setDeviceCodeLifetimeLookupStrategy(
            @SuppressWarnings("rawtypes") @Nullable final Function<ProfileRequestContext, Long> strategy) {
        deviceCodeLifetimeLookupStrategy = strategy;
    }

    /**
     * Set the lifetime of an device/user code.
     * 
     * @param lifetime lifetime of an device/user code in milliseconds
     */
    @Duration
    public void setDeviceCodeLifetime(@Positive @Duration final long lifetime) {
        deviceCodeLifetime = Constraint.isGreaterThan(0, lifetime, "device/user code lifetime must be greater than 0");
    }

    /**
     * Get device code lifetime.
     * 
     * @return device code lifetime is ms.
     */
    @Positive
    @Duration
    public long getDeviceCodeLifetime() {
        return Constraint.isGreaterThan(0, getIndirectProperty(deviceCodeLifetimeLookupStrategy, deviceCodeLifetime),
                "device code lifetime must be greater than 0");
    }

}
