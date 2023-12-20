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
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Predicate;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.config.SecurityConfiguration;

import fi.csc.shibboleth.plugin.oauth2.config.OAuth2DeviceGrantConfiguration;

public class DefaultOAuth2DeviceGrantConfiguration implements OAuth2DeviceGrantConfiguration {

    @Override
    public String getAccessTokenType(ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Duration getAccessTokenLifetime(ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return null;
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
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Integer getUserCodeLength(ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Duration getPollingInterval(ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Duration getDeviceCodeLifetime(ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return null;
    }

}
