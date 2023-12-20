package fi.csc.shibboleth.plugin.oauth2.profile.impl;

import java.time.Duration;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Predicate;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.config.SecurityConfiguration;

import fi.csc.shibboleth.plugin.oauth2.OAuth2DeviceGrantConfiguration;

class DefaultConfiguration implements OAuth2DeviceGrantConfiguration {

    @Override
    public String getAccessTokenType(ProfileRequestContext profileRequestContext) {
        return "JWT";
    }

    @Override
    public Duration getAccessTokenLifetime(ProfileRequestContext profileRequestContext) {
        return Duration.ofMinutes(10);
    }

    @Override
    public BiFunction<ProfileRequestContext, Map<String, Object>, Map<String, Object>> getAccessTokenClaimsSetManipulationStrategy(
            ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Predicate<ProfileRequestContext> getActivationCondition() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public SecurityConfiguration getSecurityConfiguration(ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int getDisallowedFeatures(ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public boolean isFeatureDisallowed(ProfileRequestContext profileRequestContext, int feature) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String getId() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Integer getDeviceCodeLength(ProfileRequestContext profileRequestContext) {
        return 10;
    }

    @Override
    public Integer getUserCodeLength(ProfileRequestContext profileRequestContext) {
        return 10;
    }

    @Override
    public Duration getPollingInterval(ProfileRequestContext profileRequestContext) {
        return Duration.ofSeconds(10);
    }

    @Override
    public Duration getDeviceCodeLifetime(ProfileRequestContext profileRequestContext) {
        return Duration.ofMinutes(10);
    }

}