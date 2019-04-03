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

package fi.csc.idpextension.oauth2.messaging.impl;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;

public class OAuth2DeviceAuthenticationRequest extends AbstractRequest {

    private final String user_code;

    public OAuth2DeviceAuthenticationRequest(URI uri, String user_code) {
        super(uri);
        this.user_code = user_code;
    }

    public String getUserCode() {
        return user_code;
    }

    @Override
    public HTTPRequest toHTTPRequest() {

        if (getEndpointURI() == null)
            throw new SerializeException("The endpoint URI is not specified");

        HTTPRequest httpRequest;
        URL endpointURL;
        try {
            endpointURL = getEndpointURI().toURL();
        } catch (MalformedURLException e) {
            throw new SerializeException(e.getMessage(), e);
        }

        httpRequest = new HTTPRequest(HTTPRequest.Method.GET, endpointURL);
        Map<String, List<String>> params = new HashMap<>();
        params.putAll(URLUtils.parseParameters(getEndpointURI().getQuery()));
        if (user_code != null) {
            params.put("user_code", Arrays.asList(user_code));
            httpRequest.setQuery(URLUtils.serializeParameters(params));
        }
        return httpRequest;
    }

    public static OAuth2DeviceAuthenticationRequest parse(final URI uri, final Map<String, List<String>> params)
            throws ParseException {

        String user_code = MultivaluedMapUtils.getFirstValue(params, "user_code");
        return new OAuth2DeviceAuthenticationRequest(uri, user_code);
    }

    public static OAuth2DeviceAuthenticationRequest parse(final URI uri, final String query) throws ParseException {
        return parse(uri, URLUtils.parseParameters(query));
    }

    public static OAuth2DeviceAuthenticationRequest parse(final HTTPRequest httpRequest) throws ParseException {

        String query = httpRequest.getQuery();
        URI endpointURI;
        try {
            endpointURI = httpRequest.getURL().toURI();
        } catch (URISyntaxException e) {
            throw new ParseException(e.getMessage(), e);
        }
        return parse(endpointURI, query);
    }

    public String toQueryString() {

        Map<String, List<String>> params = new HashMap<>();
        if (getEndpointURI() != null) {
            params.putAll(URLUtils.parseParameters(getEndpointURI().getQuery()));
        }
        if (user_code != null) {
            params.put("user_code", Arrays.asList(user_code));
        }

        return URLUtils.serializeParameters(params);
    }

}
