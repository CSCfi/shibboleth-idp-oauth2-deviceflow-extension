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

package fi.csc.shibboleth.plugin.oauth2.profile.impl;

import java.io.IOException;
import java.time.Duration;
import java.util.function.BiPredicate;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.ReplayCache;
import org.opensaml.storage.RevocationCache;
import org.opensaml.storage.VersionMismatchException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;
import com.nimbusds.oauth2.sdk.id.ClientID;

import fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.DeviceEventIds;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodesCache;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceStateObject;
import net.shibboleth.idp.plugin.oidc.op.messaging.context.OIDCAuthenticationResponseContext;
import net.shibboleth.idp.plugin.oidc.op.profile.context.navigate.DefaultDPoPProofThumbprintLookupFunction;
import net.shibboleth.idp.plugin.oidc.op.profile.impl.AbstractOIDCTokenResponseAction;
import net.shibboleth.idp.plugin.oidc.op.profile.logic.DefaultChainRevocationLifetimeLookupStrategy;
import net.shibboleth.idp.plugin.oidc.op.storage.RevocationCacheContexts;
import net.shibboleth.idp.plugin.oidc.op.token.support.AuthorizeCodeClaimsSet;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.oidc.profile.core.OidcEventIds;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.shared.annotation.ParameterName;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.security.DataExpiredException;
import net.shibboleth.shared.security.DataSealer;
import net.shibboleth.shared.security.DataSealerException;

/**
 * Validates a device code grant and sets the grant claims set of an approved device code to the response context.
 */
public class ValidateDeviceCodeGrant extends AbstractOIDCTokenResponseAction {

    /** Increase of the polling interval on slow_down, in milliseconds. */
    public static final long SLOW_DOWN_INCREMENT = 5000;

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateDeviceCodeGrant.class);

    /** Data sealer for unwrapping the grant claims set. */
    @Nonnull private final DataSealer dataSealer;

    /** Cache for device codes and device states. */
    @NonnullAfterInit private DeviceCodesCache deviceCodesCache;

    /** Replay cache for the one time use of the grant. */
    @NonnullAfterInit private ReplayCache replayCache;

    /** Revocation cache for the tokens of a replayed grant. */
    @NonnullAfterInit private RevocationCache revocationCache;

    /** Lookup function to supply chain revocation lifetime. */
    @Nonnull private Function<ProfileRequestContext, Duration> chainRevocationLifetimeLookupStrategy;

    /** Predicate used to indicate whether the grant is revoked. */
    @Nullable private BiPredicate<ProfileRequestContext, JWTClaimsSet> tokenRevocationCondition;

    /** Strategy used to locate the {@link RelyingPartyContext}. */
    @Nonnull private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Strategy used to locate the DPoP proof thumbprint. */
    @Nonnull private Function<ProfileRequestContext, String> dpopProofThumbprintLookupStrategy;

    /** Relying party context. */
    @Nullable private RelyingPartyContext rpCtx;

    /**
     * Constructor.
     *
     * @param sealer sealer to unwrap the grant claims set
     */
    public ValidateDeviceCodeGrant(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
        dpopProofThumbprintLookupStrategy = new DefaultDPoPProofThumbprintLookupFunction();
        final DefaultChainRevocationLifetimeLookupStrategy lifetimeStrategy =
                new DefaultChainRevocationLifetimeLookupStrategy();
        lifetimeStrategy.setUseActiveProfileOnly(false);
        chainRevocationLifetimeLookupStrategy = lifetimeStrategy;
    }

    /**
     * Set the device code cache.
     *
     * @param cache device code cache
     */
    public void setDeviceCodesCache(@Nonnull final DeviceCodesCache cache) {
        checkSetterPreconditions();
        deviceCodesCache = Constraint.isNotNull(cache, "DeviceCodesCache cannot be null");
    }

    /**
     * Set the replay cache.
     *
     * @param cache replay cache
     */
    public void setReplayCache(@Nonnull final ReplayCache cache) {
        checkSetterPreconditions();
        replayCache = Constraint.isNotNull(cache, "ReplayCache cannot be null");
    }

    /**
     * Set the revocation cache.
     *
     * @param cache revocation cache
     */
    public void setRevocationCache(@Nonnull final RevocationCache cache) {
        checkSetterPreconditions();
        revocationCache = Constraint.isNotNull(cache, "RevocationCache cannot be null");
    }

    /**
     * Set a lookup strategy for the chain revocation lifetime.
     *
     * @param strategy lookup strategy
     */
    public void setChainRevocationLifetimeLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, Duration> strategy) {
        checkSetterPreconditions();
        chainRevocationLifetimeLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /**
     * Set the predicate used to indicate whether the grant is revoked.
     *
     * @param condition token revocation condition
     */
    public void setTokenRevocationCondition(
            @Nullable final BiPredicate<ProfileRequestContext, JWTClaimsSet> condition) {
        checkSetterPreconditions();
        tokenRevocationCondition = condition;
    }

    /**
     * Set the strategy used to locate the {@link RelyingPartyContext}.
     *
     * @param strategy lookup strategy
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        checkSetterPreconditions();
        relyingPartyContextLookupStrategy =
                Constraint.isNotNull(strategy, "RelyingPartyContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the DPoP proof thumbprint.
     *
     * @param strategy lookup strategy
     */
    public void setDpopProofThumbprintLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        checkSetterPreconditions();
        dpopProofThumbprintLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (deviceCodesCache == null || replayCache == null || revocationCache == null) {
            throw new ComponentInitializationException(
                    "DeviceCodesCache, ReplayCache and RevocationCache cannot be null");
        }
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null) {
            log.error("{} No relying party context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        return true;
    }

    // Checkstyle: CyclomaticComplexity|MethodLength|ReturnCount OFF
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final AuthorizationGrant grant = getTokenRequest().getAuthorizationGrant();
        if (!(grant instanceof DeviceCodeGrant)) {
            log.warn("{} Grant type {} not supported", getLogPrefix(), grant.getType());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        final String deviceCode = ((DeviceCodeGrant) grant).getDeviceCode().getValue();
        final Pair<Long, DeviceStateObject> versionedState;
        try {
            versionedState = deviceCodesCache.getVersionedDeviceState(deviceCode);
        } catch (final IOException | net.minidev.json.parser.ParseException e) {
            log.error("{} Error reading the device code state", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return;
        }
        final DeviceStateObject stateObject = versionedState != null ? versionedState.getSecond() : null;
        if (stateObject == null) {
            log.debug("{} Device code is unknown or has expired", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.EXPIRED_TOKEN);
            return;
        }
        assert rpCtx != null;
        final String relyingPartyId = rpCtx.getRelyingPartyId();
        if (stateObject.getClientId() == null || !stateObject.getClientId().equals(relyingPartyId)) {
            log.warn("{} Device code issued to client {}, invalid for {}", getLogPrefix(),
                    stateObject.getClientId(), relyingPartyId);
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        if (stateObject.getState() == DeviceStateObject.State.PENDING) {
            final long now = System.currentTimeMillis();
            final Long interval = stateObject.getInterval();
            final Long lastPoll = stateObject.getLastPoll();
            final boolean slowDown = interval != null && lastPoll != null && now - lastPoll < interval;
            final Long newInterval = slowDown ? Long.valueOf(interval + SLOW_DOWN_INCREMENT) : interval;
            final Long version = versionedState.getFirst();
            assert version != null;
            try {
                if (!deviceCodesCache.updateDeviceState(deviceCode, stateObject.withPoll(now, newInterval),
                        version)) {
                    log.debug("{} Device code expired while polling", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.EXPIRED_TOKEN);
                    return;
                }
            } catch (final VersionMismatchException e) {
                log.debug("{} Device code state changed while polling", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.AUTHORIZATION_PENDING);
                return;
            } catch (final IOException e) {
                log.error("{} Error storing the poll time of the device code", getLogPrefix(), e);
                ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
                return;
            }
            if (slowDown) {
                log.debug("{} Device code polled after {} ms, interval {} ms, new interval {} ms", getLogPrefix(),
                        now - lastPoll, interval, newInterval);
                ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.SLOW_DOWN);
                return;
            }
            log.debug("{} Request is still pending", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.AUTHORIZATION_PENDING);
            return;
        }
        if (stateObject.getState() == DeviceStateObject.State.DENIED) {
            log.debug("{} User has denied the request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.USER_DENIED);
            return;
        }
        final String wrappedGrant = stateObject.getAccessToken();
        if (wrappedGrant == null) {
            log.error("{} Approved device code has no grant claims set", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        final AuthorizeCodeClaimsSet claimsSet;
        try {
            claimsSet = AuthorizeCodeClaimsSet.parse(wrappedGrant, dataSealer);
        } catch (final DataExpiredException e) {
            log.warn("{} Grant of the device code has expired", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.EXPIRED_TOKEN);
            return;
        } catch (final DataSealerException | java.text.ParseException e) {
            log.warn("{} Unwrapping the grant of the device code failed: {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        log.debug("{} Grant of the device code unwrapped {}", getLogPrefix(), claimsSet.serialize());
        final String jti = claimsSet.getID();
        if (jti == null) {
            log.warn("{} Invalid grant of the device code: no JTI", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        final String cacheContext = getClass().getName();
        assert cacheContext != null;
        if (!replayCache.check(cacheContext, jti, claimsSet.getExp())) {
            log.error("{} Replay detected of device code grant {}", getLogPrefix(), jti);
            if (!revokeChain(jti, chainRevocationLifetimeLookupStrategy.apply(profileRequestContext))) {
                log.warn("{} Fatal error, unable to save replayed grant to revocation cache", getLogPrefix());
            }
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        if (!claimsSet.isTimeValid()) {
            log.warn("{} Grant {} is expired or not yet valid", getLogPrefix(), jti);
            ActionSupport.buildEvent(profileRequestContext, DeviceEventIds.EXPIRED_TOKEN);
            return;
        }
        if (tokenRevocationCondition != null
                && tokenRevocationCondition.test(profileRequestContext, claimsSet.getClaimsSet())) {
            log.warn("{} Grant {} has been revoked by the token revocation condition", getLogPrefix(), jti);
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        final ClientID clientId = claimsSet.getClientID();
        if (clientId == null || !clientId.getValue().equals(relyingPartyId)) {
            log.warn("{} Grant {} issued to client {}, invalid for {}", getLogPrefix(), jti,
                    clientId != null ? clientId.getValue() : null, relyingPartyId);
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT);
            return;
        }
        log.debug("{} Grant {} used for the first time", getLogPrefix(), jti);
        final OIDCAuthenticationResponseContext oidcResponseContext = getOidcResponseContext();
        assert oidcResponseContext != null;
        oidcResponseContext.setAuthorizationGrantClaimsSet(claimsSet);
        final String proofThumbprint = dpopProofThumbprintLookupStrategy.apply(profileRequestContext);
        log.debug("{} DPoP proof thumbprint for the access token: {}", getLogPrefix(), proofThumbprint);
        oidcResponseContext.setDpopProofJwkThumbprint(proofThumbprint);
    }
    // Checkstyle: CyclomaticComplexity|MethodLength|ReturnCount ON

    /**
     * Revokes the token chain with the given id, optionally with a given lifetime. If the given lifetime is null,
     * the default lifetime set to the {@link RevocationCache} is used.
     *
     * @param id the identifier to be revoked in {@link RevocationCacheContexts#AUTHORIZATION_CODE} context
     * @param lifetime the lifetime for the revocation
     * @return the result returned by the {@link RevocationCache}
     */
    protected boolean revokeChain(@Nonnull final String id, @Nullable final Duration lifetime) {
        if (lifetime == null) {
            log.warn("{} No profile-specific revocation lifetime could be resolved, using default value",
                    getLogPrefix());
            return revocationCache.revoke(RevocationCacheContexts.AUTHORIZATION_CODE, id);
        }
        return revocationCache.revoke(RevocationCacheContexts.AUTHORIZATION_CODE, id, lifetime);
    }

}
