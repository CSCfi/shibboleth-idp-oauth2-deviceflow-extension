/*
 * Copyright (c) 2026 CSC- IT Center for Science, www.csc.fi
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

import java.security.SecureRandom;
import java.util.Locale;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Generation and normalization of device grant user codes.
 */
public final class UserCodeSupport {

    /** User code character set, the base-20 consonants of RFC 8628 section 6.1. */
    @Nonnull public static final String CHARACTER_SET = "BCDFGHJKLMNPQRSTVWXZ";

    /** Source of randomness. */
    @Nonnull private static final SecureRandom RANDOM = new SecureRandom();

    /** Constructor. */
    private UserCodeSupport() {
    }

    /**
     * Generate a user code.
     *
     * @param length length of the user code
     * @return user code
     */
    @Nonnull public static String generate(final int length) {
        final StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARACTER_SET.charAt(RANDOM.nextInt(CHARACTER_SET.length())));
        }
        return sb.toString();
    }

    /**
     * Normalize a user code entered by the user: upper case, letters and digits only.
     *
     * @param userCode user code as entered
     * @return normalized user code, or null if nothing remains
     */
    @Nullable public static String normalize(@Nullable final String userCode) {
        if (userCode == null) {
            return null;
        }
        final StringBuilder sb = new StringBuilder(userCode.length());
        for (final char c : userCode.toUpperCase(Locale.ROOT).toCharArray()) {
            if (Character.isLetterOrDigit(c)) {
                sb.append(c);
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }
}
