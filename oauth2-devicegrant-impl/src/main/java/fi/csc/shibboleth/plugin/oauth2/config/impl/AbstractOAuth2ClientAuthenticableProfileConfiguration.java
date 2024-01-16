/*
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

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Predicates;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

import net.shibboleth.idp.profile.config.AbstractInterceptorAwareProfileConfiguration;
import net.shibboleth.oidc.authn.principal.AuthenticationContextClassReferencePrincipal;
import net.shibboleth.oidc.jwt.claims.ClaimsValidator;
import net.shibboleth.oidc.metadata.policy.UnregisteredClientPolicy;
import net.shibboleth.oidc.profile.oauth2.config.OAuth2ClientAuthenticableClientProfileConfiguration;
import net.shibboleth.oidc.profile.oauth2.config.OAuth2ClientAuthenticableProfileConfiguration;
import net.shibboleth.oidc.security.credential.ClientSecretCredential;
import net.shibboleth.shared.annotation.constraint.NonNegative;
import net.shibboleth.shared.annotation.constraint.NonnullElements;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Unmodifiable;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.logic.FunctionSupport;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * Base class for OAuth profile configurations that support OAuth-defined client
 * authentication methods.
 */
public abstract class AbstractOAuth2ClientAuthenticableProfileConfiguration
        extends AbstractInterceptorAwareProfileConfiguration
        implements OAuth2ClientAuthenticableProfileConfiguration, OAuth2ClientAuthenticableClientProfileConfiguration {

    /** Enabled token endpoint authentication methods. */
    @Nonnull
    private Function<ProfileRequestContext, Set<String>> tokenEndpointAuthMethodsLookupStrategy;

    /**
     * The token endpoint authentication method to use with an upstream OpenID
     * Provider.
     */
    @Nonnull
    private Function<ProfileRequestContext, String> tokenEndpointAuthMethodLookupStrategy;

    /** Validation of JWT claims for subset of client auth methods. */
    @Nonnull
    private Function<ProfileRequestContext, ClaimsValidator> claimsValidatorLookupStrategy;

    /** Whether to mandate forced authentication for the request. */
    @Nonnull
    private Predicate<ProfileRequestContext> forceAuthnPredicate;

    /** Lookup function to supply proxyCount property. */
    @Nonnull
    private Function<ProfileRequestContext, Integer> proxyCountLookupStrategy;

    /** Lookup function to supply default authentication methods. */
    @Nonnull
    private Function<ProfileRequestContext, Collection<AuthenticationContextClassReferencePrincipal>> defaultAuthenticationContextsLookupStrategy;

    /** Lookup function to supply authentication flows. */
    @Nonnull
    private Function<ProfileRequestContext, Set<String>> authenticationFlowsLookupStrategy;

    /** Lookup function to supply post authentication flows. */
    @Nonnull
    private Function<ProfileRequestContext, Collection<String>> postAuthenticationFlowsLookupStrategy;

    /**
     * Lookup function to retrieve a client credential from the given profile
     * request context.
     */
    @Nonnull
    private Function<ProfileRequestContext, ClientSecretCredential> clientCredentialLookupStrategy;

    /**
     * Lookup function to retrieve the client_id from the given profile request
     * context.
     */
    // TODO this is the same as the issuer in the proxy context?
    @Nonnull
    private Function<ProfileRequestContext, String> clientIdLookupStrategy;

    /**
     * Lookup function to retrieve the policy for validating claims of an
     * unregistered client.
     */
    @Nonnull
    private Function<ProfileRequestContext, Map<String, UnregisteredClientPolicy>> unregisteredClientPolicyLookupStrategy;

    /**
     * Constructor.
     *
     * @param profileId Unique profile identifier
     */
    protected AbstractOAuth2ClientAuthenticableProfileConfiguration(@Nonnull @NotEmpty final String profileId) {
        super(profileId);

        setTokenEndpointAuthMethods(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.toString(),
                ClientAuthenticationMethod.CLIENT_SECRET_POST.toString(),
                ClientAuthenticationMethod.CLIENT_SECRET_JWT.toString(),
                ClientAuthenticationMethod.PRIVATE_KEY_JWT.toString()));
        tokenEndpointAuthMethodLookupStrategy = FunctionSupport
                .constant(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.toString());
        claimsValidatorLookupStrategy = FunctionSupport.constant(null);
        forceAuthnPredicate = Predicates.alwaysFalse();
        proxyCountLookupStrategy = FunctionSupport.constant(null);
        defaultAuthenticationContextsLookupStrategy = FunctionSupport.constant(null);
        authenticationFlowsLookupStrategy = FunctionSupport.constant(null);
        postAuthenticationFlowsLookupStrategy = FunctionSupport.constant(null);
        clientCredentialLookupStrategy = FunctionSupport.constant(null);
        clientIdLookupStrategy = FunctionSupport.constant(null);
        unregisteredClientPolicyLookupStrategy = FunctionSupport.constant(null);
    }

    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public Set<String> getTokenEndpointAuthMethods(@Nullable final ProfileRequestContext profileRequestContext) {

        final Collection<String> methods = tokenEndpointAuthMethodsLookupStrategy.apply(profileRequestContext);
        if (methods != null) {
            return Set.copyOf(methods);
        }
        return Collections.emptySet();
    }

    /**
     * Set the enabled token endpoint authentication methods.
     *
     * @param methods What to set.
     */
    public void setTokenEndpointAuthMethods(@Nonnull @NonnullElements final Collection<String> methods) {
        Constraint.isNotNull(methods, "Collection of methods cannot be null");

        if (methods != null) {
            tokenEndpointAuthMethodsLookupStrategy = FunctionSupport
                    .constant(Set.copyOf(StringSupport.normalizeStringCollection(methods)));
        } else {
            tokenEndpointAuthMethodsLookupStrategy = FunctionSupport.constant(null);
        }
    }

    /**
     * Set a lookup strategy for the enabled token endpoint authentication methods.
     *
     * @param strategy lookup strategy
     */
    public void setTokenEndpointAuthMethodsLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, Set<String>> strategy) {
        tokenEndpointAuthMethodsLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    @Override
    @Nonnull
    public String getTokenEndpointAuthMethod(@Nullable final ProfileRequestContext profileRequestContext) {
        return tokenEndpointAuthMethodLookupStrategy.apply(profileRequestContext);
    }

    /**
     * Set the enabled token endpoint authentication method to use with an upstream
     * OpenID Provider.
     *
     * @param method the token endpoint authentication method to set.
     *
     * @since 2.2.0
     */
    public void setTokenEndpointAuthMethod(@Nonnull @NonnullElements final String method) {
        tokenEndpointAuthMethodLookupStrategy = FunctionSupport
                .constant(Constraint.isNotNull(method, "Collection of methods cannot be null"));
    }

    /**
     * Set a lookup strategy to find the enabled token endpoint authentication
     * method to use with an upstream OpenID Provider.
     *
     * @param strategy lookup strategy
     *
     * @since 2.2.0
     */
    public void setTokenEndpointAuthMethodLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, String> strategy) {
        tokenEndpointAuthMethodLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /**
     * Get the {@link ClaimsValidator} to apply to JWT-based client authentication.
     *
     * @param profileRequestContext current profile request context
     *
     * @return the validator to use
     *
     * @since 3.1.0
     */
    @Override
    @Nullable
    public ClaimsValidator getClaimsValidator(@Nullable final ProfileRequestContext profileRequestContext) {
        return claimsValidatorLookupStrategy.apply(profileRequestContext);
    }

    /**
     * Set the {@link ClaimsValidator} to apply to JWT-based client authentication.
     *
     * @param validator validator to use
     *
     * @since 3.1.0
     */
    public void setClaimsValidator(@Nullable final ClaimsValidator validator) {
        claimsValidatorLookupStrategy = FunctionSupport.constant(validator);
    }

    /**
     * Set a lookup strategy for the {@link ClaimsValidator} to apply to JWT-based
     * client authentication.
     *
     * @param strategy lookup strategy
     *
     * @since 3.1.0
     */
    public void setClaimsValidatorLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, ClaimsValidator> strategy) {
        claimsValidatorLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    public boolean isForceAuthn(@Nullable final ProfileRequestContext profileRequestContext) {
        return forceAuthnPredicate.test(profileRequestContext);
    }

    /**
     * Set whether a fresh user presence proof should be required for this request.
     *
     * @param flag flag to set
     */
    public void setForceAuthn(final boolean flag) {
        forceAuthnPredicate = flag ? Predicates.alwaysTrue() : Predicates.alwaysFalse();
    }

    /**
     * Set a condition to determine whether a fresh user presence proof should be
     * required for this request.
     *
     * @param condition condition to set
     */
    public void setForceAuthnPredicate(@Nonnull final Predicate<ProfileRequestContext> condition) {
        forceAuthnPredicate = Constraint.isNotNull(condition, "Forced authentication predicate cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Integer getProxyCount(@Nullable final ProfileRequestContext profileRequestContext) {
        final Integer count = proxyCountLookupStrategy.apply(profileRequestContext);
        if (count != null) {
            Constraint.isGreaterThanOrEqual(0, count, "Proxy count must be greater than or equal to 0");
        }
        return count;
    }

    /**
     * Sets the maximum number of times an assertion may be proxied outbound and/or
     * the maximum number of hops between the relying party and a proxied
     * authentication authority inbound.
     *
     * @param count proxy count
     */
    public void setProxyCount(@Nullable @NonNegative final Integer count) {
        if (count != null) {
            Constraint.isGreaterThanOrEqual(0, count, "Proxy count must be greater than or equal to 0");
        }
        proxyCountLookupStrategy = FunctionSupport.constant(count);
    }

    /**
     * Set a lookup strategy for the maximum number of times an assertion may be
     * proxied outbound and/or the maximum number of hops between the relying party
     * and a proxied authentication authority inbound.
     *
     * @param strategy lookup strategy
     */
    public void setProxyCountLookupStrategy(@Nonnull final Function<ProfileRequestContext, Integer> strategy) {
        proxyCountLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public Set<String> getAuthenticationFlows(@Nullable final ProfileRequestContext profileRequestContext) {
        final Set<String> flows = authenticationFlowsLookupStrategy.apply(profileRequestContext);
        if (flows != null) {
            return Set.copyOf(flows);
        }
        return Collections.emptySet();
    }

    /**
     * Set the authentication flows to use.
     *
     * @param flows flow identifiers to use
     */
    public void setAuthenticationFlows(@Nullable @NonnullElements final Collection<String> flows) {
        if (flows != null) {
            authenticationFlowsLookupStrategy = FunctionSupport
                    .constant(Set.copyOf(StringSupport.normalizeStringCollection(flows)));
        } else {
            authenticationFlowsLookupStrategy = FunctionSupport.constant(null);
        }
    }

    /**
     * Set a lookup strategy for the authentication flows to use.
     *
     * @param strategy lookup strategy
     */
    public void setAuthenticationFlowsLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, Set<String>> strategy) {
        authenticationFlowsLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<String> getPostAuthenticationFlows(@Nullable final ProfileRequestContext profileRequestContext) {
        final Collection<String> flows = postAuthenticationFlowsLookupStrategy.apply(profileRequestContext);
        if (flows != null) {
            return List.copyOf(flows);
        }
        return Collections.emptyList();
    }

    /**
     * Set the ordered collection of post-authentication interceptor flows to
     * enable.
     *
     * @param flows flow identifiers to enable
     */
    public void setPostAuthenticationFlows(@Nullable @NonnullElements final Collection<String> flows) {
        if (flows != null) {
            postAuthenticationFlowsLookupStrategy = FunctionSupport
                    .constant(List.copyOf(StringSupport.normalizeStringCollection(flows)));
        } else {
            postAuthenticationFlowsLookupStrategy = FunctionSupport.constant(null);
        }
    }

    /**
     * Set a lookup strategy for the post-authentication interceptor flows to
     * enable.
     *
     * @param strategy lookup strategy
     */
    public void setPostAuthenticationFlowsLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, Collection<String>> strategy) {
        postAuthenticationFlowsLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<Principal> getDefaultAuthenticationMethods(
            @Nullable final ProfileRequestContext profileRequestContext) {
        final Collection<AuthenticationContextClassReferencePrincipal> methods = defaultAuthenticationContextsLookupStrategy
                .apply(profileRequestContext);
        if (methods != null) {
            return List.copyOf(methods);
        }
        return Collections.emptyList();
    }

    /**
     * Set the default authentication contexts to use, expressed as custom
     * principals.
     *
     * @param contexts default authentication contexts to use
     */
    public void setDefaultAuthenticationMethods(
            @Nullable @NonnullElements final Collection<AuthenticationContextClassReferencePrincipal> contexts) {
        if (contexts != null) {
            defaultAuthenticationContextsLookupStrategy = FunctionSupport.constant(List.copyOf(contexts));
        } else {
            defaultAuthenticationContextsLookupStrategy = FunctionSupport.constant(null);
        }
    }

    /**
     * Set a lookup strategy for the authentication contexts to use, expressed as
     * custom principals.
     *
     * @param strategy lookup strategy
     */
    public void setDefaultAuthenticationMethodsLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, Collection<AuthenticationContextClassReferencePrincipal>> strategy) {
        defaultAuthenticationContextsLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /**
     * Set the client credential lookup strategy.
     *
     * @param strategy the strategy to use
     *
     * @since 2.2.0
     */
    public void setClientCredentialLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, ClientSecretCredential> strategy) {
        clientCredentialLookupStrategy = Constraint.isNotNull(strategy,
                "Client credential lookup strategy can not be null");
    }

    /**
     * Set a fixed client credential to use no matter what the context/request.
     *
     * @param clientCredential the static client credential to use
     *
     * @since 2.2.0
     */
    public void setClientCredential(@Nullable final ClientSecretCredential clientCredential) {
        clientCredentialLookupStrategy = FunctionSupport.constant(clientCredential);
    }

    @Override
    public ClientSecretCredential getClientCredential(@Nullable final ProfileRequestContext profileRequestContext) {
        return clientCredentialLookupStrategy.apply(profileRequestContext);
    }

    /**
     * Set the strategy to locate a client_id.
     *
     * @param strategy the strategy to use
     *
     * @since 2.2.0
     */
    public void setClientIdLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        clientIdLookupStrategy = Constraint.isNotNull(strategy, "Client ID lookup strategy can not be null");
    }

    /**
     * Set a fixed client_id to use no matter what the context/request.
     *
     * @param clientId the static clientId to use
     *
     * @since 2.2.0
     */
    public void setClientId(@Nullable final String clientId) {
        clientIdLookupStrategy = FunctionSupport.constant(StringSupport.trimOrNull(clientId));
    }

    @Override
    @Nullable
    public String getClientId(@Nullable final ProfileRequestContext profileRequestContext) {
        return clientIdLookupStrategy.apply(profileRequestContext);
    }

    @Override
    @Nullable
    @Unmodifiable
    public Map<String, UnregisteredClientPolicy> getUnregisteredClientPolicy(
            @Nullable final ProfileRequestContext profileRequestContext) {
        return unregisteredClientPolicyLookupStrategy.apply(profileRequestContext);
    }

    /**
     * Sets the policy for validating unregistered clients.
     *
     * @param policy policy to set
     *
     * @since 3.0.0
     */
    public void setUnregisteredClientPolicy(@Nullable final Map<String, UnregisteredClientPolicy> policy) {
        unregisteredClientPolicyLookupStrategy = FunctionSupport.constant(policy);
    }

    /**
     * Set a lookup strategy for the policy for validating unregistered clients.
     *
     * @param strategy lookup strategy
     *
     * @since 3.0.0
     */
    public void setUnregisteredClientPolicyLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, Map<String, UnregisteredClientPolicy>> strategy) {
        unregisteredClientPolicyLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

}
