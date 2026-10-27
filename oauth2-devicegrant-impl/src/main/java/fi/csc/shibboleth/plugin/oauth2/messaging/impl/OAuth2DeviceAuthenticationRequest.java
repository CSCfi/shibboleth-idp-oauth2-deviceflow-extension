/*
 * Copyright (c) 2019-2024 CSC- IT Center for Science, www.csc.fi
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

package fi.csc.shibboleth.plugin.oauth2.messaging.impl;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;

/**
 * Class implementing Authentication Request message for https://tools.ietf.org/html/rfc8628.
 */
public class OAuth2DeviceAuthenticationRequest extends AbstractRequest {

    /**
     * The end-user verification code described in
     * https://tools.ietf.org/html/rfc8628#section-3.2.
     */
    private final String userCode;

    /**
     * Constructor.
     * 
     * @param uri The URI of the endpoint (HTTP or HTTPS) for which the request is intended, {@code null} if not
     *            specified (if, for example, the {@link #toHTTPRequest()} method will not be used).
     * @param userCode The end-user verification code.
     */
    public OAuth2DeviceAuthenticationRequest(@Nonnull final URI uri, @Nullable final String userCode) {
        super(uri);
        this.userCode = userCode;
    }

    /**
     * Get end-user verification code.
     * 
     * @return end-user verification code
     */
    @Nullable
    public String getUserCode() {
        return userCode;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public HTTPRequest toHTTPRequest() {

        if (getEndpointURI() == null) {
            throw new SerializeException("The endpoint URI is not specified");
        }

        final HTTPRequest httpRequest;
        final URL endpointURL;
        try {
            endpointURL = getEndpointURI().toURL();
        } catch (final MalformedURLException e) {
            throw new SerializeException(e.getMessage(), e);
        }

        httpRequest = new HTTPRequest(HTTPRequest.Method.GET, endpointURL);
        final Map<String, List<String>> params = new HashMap<>();
        params.putAll(URLUtils.parseParameters(getEndpointURI().getQuery()));
        if (userCode != null) {
            params.put("user_code", Arrays.asList(userCode));
            httpRequest.setQuery(URLUtils.serializeParameters(params));
        }
        return httpRequest;
    }

    /**
     * Parses request from uri and parameters. Only user_code parameter is supported, others ignored.
     * 
     * @param uri The URI of the endpoint (HTTP or HTTPS) for which the request is intended.
     * @param params request parameters, only user_code is supported, others ignored.
     * @return parsed request.
     * @throws ParseException if parsing failed.
     */
    public static OAuth2DeviceAuthenticationRequest parse(final URI uri, final Map<String, List<String>> params)
            throws ParseException {

        final String userCode = MultivaluedMapUtils.getFirstValue(params, "user_code");
        return new OAuth2DeviceAuthenticationRequest(uri, userCode);
    }

    /**
     * Parses request from uri and parameters. Only user_code parameter is supported, others ignored.
     * 
     * @param uri The URI of the endpoint (HTTP or HTTPS) for which the request is intended.
     * @param query request parameters in query string. Only user_code is supported, others ignored.
     * @return parsed request.
     * @throws ParseException if parsing failed.
     */
    public static OAuth2DeviceAuthenticationRequest parse(final URI uri, final String query) throws ParseException {
        return parse(uri, URLUtils.parseParameters(query));
    }

    /**
     * Parses request from http request. Only user_code parameter is supported, others ignored.
     * 
     * @param httpRequest request to parse.
     * @return parsed request.
     * @throws ParseException if parsing failed.
     */
    public static OAuth2DeviceAuthenticationRequest parse(final HTTPRequest httpRequest) throws ParseException {

        final String query = httpRequest.getQuery();
        final URI endpointURI;
        try {
            endpointURI = httpRequest.getURL().toURI();
        } catch (final URISyntaxException e) {
            throw new ParseException(e.getMessage(), e);
        }
        return parse(endpointURI, query);
    }

    /**
     * Request parameters as query string.
     * 
     * @return request parameters as query string
     */
    public String toQueryString() {

        final Map<String, List<String>> params = new HashMap<>();
        if (getEndpointURI() != null) {
            params.putAll(URLUtils.parseParameters(getEndpointURI().getQuery()));
        }
        if (userCode != null) {
            params.put("user_code", Arrays.asList(userCode));
        }
        return URLUtils.serializeParameters(params);
    }

}
