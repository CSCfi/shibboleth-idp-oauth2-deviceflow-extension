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

package fi.csc.idpextension.oauth2.profile;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * OAuth2 Device Flow -specific constants to use for {@link org.opensaml.profile.action.ProfileAction}
 * {@link org.opensaml.profile.context.EventContext}s.
 */
public final class DeviceEventIds {

    /**
     * ID of event returned if user code is not available.
     */
    @Nonnull
    @NotEmpty
    public static final String NO_USER_CODE = "NoUserCode";

    /**
     * ID of event returned if user has not responded yet.
     */
    @Nonnull
    @NotEmpty
    public static final String AUTHORIZATION_PENDING = "AuthorizationPending";

    /**
     * ID of event returned if user has denied the request.
     */
    @Nonnull
    @NotEmpty
    public static final String USER_DENIED = "UserDenied";

    /**
     * ID of event returned if device code has expired.
     */
    @Nonnull
    @NotEmpty
    public static final String EXPIRED_TOKEN = "ExpiredToken";

    /**
     * Constructor.
     */
    private DeviceEventIds() {
        // no op
    }

}
