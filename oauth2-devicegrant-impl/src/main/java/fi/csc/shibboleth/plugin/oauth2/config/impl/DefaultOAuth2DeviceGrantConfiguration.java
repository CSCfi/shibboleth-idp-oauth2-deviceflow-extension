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

import org.opensaml.profile.context.ProfileRequestContext;

import fi.csc.shibboleth.plugin.oauth2.config.OAuth2DeviceGrantConfiguration;

//TODO Implementation
public class DefaultOAuth2DeviceGrantConfiguration extends AbstractOAuth2ClientAuthenticableProfileConfiguration
        implements OAuth2DeviceGrantConfiguration {

    protected DefaultOAuth2DeviceGrantConfiguration() {
        super(OAuth2DeviceGrantConfiguration.PROFILE_ID);
        // TODO Auto-generated constructor stub
    }

    @Override
    public Integer getDeviceCodeLength(ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return 8;
    }

    @Override
    public Integer getUserCodeLength(ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return 8;
    }

    @Override
    public Duration getPollingInterval(ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return Duration.ofSeconds(5);
    }

    @Override
    public Duration getDeviceCodeLifetime(ProfileRequestContext profileRequestContext) {
        // TODO Auto-generated method stub
        return Duration.ofMinutes(10);
    }

}
