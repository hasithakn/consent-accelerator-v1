/**
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
 * <p>
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.financial.services.accelerator.authentication.endpoint;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.financial.services.accelerator.authentication.endpoint.util.AuthenticationUtils;
import org.wso2.financial.services.accelerator.authentication.endpoint.util.Constants;
import org.wso2.financial.services.accelerator.authentication.endpoint.util.LocalCacheUtil;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * The servlet responsible for the confirm page in auth web flow.
 */
public class FSConsentConfirmServlet extends HttpServlet {

    private static final long serialVersionUID = 6106269597832678046L;
    private static Logger log = LoggerFactory.getLogger(FSConsentConfirmServlet.class);

    @SuppressFBWarnings("COOKIE_USAGE")
    // Suppressed content - browserCookies.put(cookie.getName(), cookie.getValue())
    // Suppression reason - False Positive : The cookie values are only read and
    // here. No sensitive info is added to
    // the cookie in this step.
    // Suppressed warning count - 1
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String sessionDataKey = request.getParameter(Constants.SESSION_DATA_KEY_CONSENT);
        HttpSession session = request.getSession();
        // validating session data key format

        // Retrieve cached dataSet using sessionDataKey
        LocalCacheUtil cache = LocalCacheUtil.getInstance();
        JSONObject cachedDataSet = cache.get(sessionDataKey, JSONObject.class);

        if (cachedDataSet != null) {
            log.info("Successfully retrieved cached dataSet for sessionDataKey: {}", sessionDataKey);
            // You can now use cachedDataSet - it contains all the consent data from FSConsentServlet
            log.debug("Cached dataSet content: {}", cachedDataSet.toString());

        } else {
            log.warn("No cached dataSet found for sessionDataKey: {}", sessionDataKey);
        }

        try {
            UUID.fromString(sessionDataKey);
        } catch (IllegalArgumentException e) {
            log.error("Invalid session data key", e);
            session.invalidate();
            response.sendRedirect("retry.do?status=Error&statusMsg=Invalid session data key");
            return;
        }


        Map<String, String> metadata = new HashMap<>();
        Map<String, String> browserCookies = new HashMap<>();
        JSONObject consentData = new JSONObject();

        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            browserCookies.put(cookie.getName(), cookie.getValue());
        }

        // Capture selected accounts and consent parameters from the form submission
        
        // Get data access duration (how far back in history)
        String dataAccessDuration = request.getParameter("dataAccessDuration");
        log.info("Data access duration selected: {} days", dataAccessDuration);
        
        // Get consent expiry (how long consent is valid)
        String consentExpiry = request.getParameter("consentExpiry");
        log.info("Consent expiry selected: {} days", consentExpiry);

        // Capture approved purposes (selected permission scopes)
        String[] approvedPurposes = request.getParameterValues("accounts");
        JSONObject approvedPurposesJson = new JSONObject();
        approvedPurposesJson.put("approved_purposes", approvedPurposes);
        log.info("Approved purposes: {}", Arrays.toString(approvedPurposes));

        String user = cachedDataSet.getString("user");
        String consentId = cachedDataSet.getString("consent_id");
        boolean approval = request.getParameter("consent") != null &&
                request.getParameter("consent").equals("true");

        // Fetch fresh consent details using consent ID if available
        JSONObject freshConsentDetails = null;
        if (consentId != null && !consentId.isEmpty()) {
            try {
                freshConsentDetails = fetchConsentDetails(consentId, getServletContext());
                if (freshConsentDetails != null) {
                    log.info("Successfully fetched fresh consent details for consent_id: {}", consentId);
                    log.debug("Fresh consent details: {}", freshConsentDetails.toString());

                    // You can now use freshConsentDetails to:
                    // - Verify consent status
                    // - Get latest consent data
                    // - Update consent with selected accounts

                    String consentStatus = freshConsentDetails.optString("status", "unknown");
                    log.info("Current consent status: {}", consentStatus);
                } else {
                    log.warn("Failed to fetch fresh consent details for consent_id: {}", consentId);
                }
            } catch (IOException e) {
                log.error("Error fetching consent details for consent_id: {}", consentId, e);
                // Continue processing even if fetching fails
            }
        }

        // Update the consent status to authorised if user approved
        if (approval && freshConsentDetails != null && consentId != null) {
            try {
                JSONObject putPayload = new JSONObject();

                JSONArray auth_resources = new JSONArray();
                JSONObject auth_resource = new JSONObject();

                putPayload.put("status", "AUTHORIZED");
                auth_resource.put("userId", user);
                auth_resource.put("type", "authorisation");
                auth_resource.put("status", "authorised");
                auth_resource.put("resource", approvedPurposesJson);
                auth_resources.put(auth_resource);

                putPayload.put("authorizations", auth_resources);

                // Calculate and add expiration timestamp based on consentExpiry
                if (consentExpiry != null && !consentExpiry.isEmpty()) {
                    try {
                        int expiryDays = Integer.parseInt(consentExpiry);
                        // Calculate future timestamp in seconds (Unix epoch time)
                        long currentTimestamp = System.currentTimeMillis() / 1000; // Current time in seconds
                        long expirySeconds = expiryDays * 24 * 60 * 60; // Convert days to seconds
                        long validityTimestamp = currentTimestamp + expirySeconds;
                        
                        putPayload.put("validityTime", validityTimestamp);
                        log.info("Set consent validity time to timestamp: {} (expires in {} days)", 
                                validityTimestamp, expiryDays);
                    } catch (NumberFormatException e) {
                        log.warn("Invalid consentExpiry value: {}", consentExpiry);
                    }
                }

                // Add data access validity duration (historical data access period in seconds)
                if (dataAccessDuration != null && !dataAccessDuration.isEmpty()) {
                    // Convert days to seconds for dataAccessValidityDuration
                    if (!"all".equals(dataAccessDuration)) {
                        try {
                            int durationDays = Integer.parseInt(dataAccessDuration);
                            // Convert days to seconds: days * 24 hours * 60 minutes * 60 seconds
                            int durationSeconds = durationDays * 24 * 60 * 60;
                            putPayload.put("dataAccessValidityDuration", durationSeconds);
                            log.info("Set data access validity duration to: {} seconds ({} days)", 
                                    durationSeconds, durationDays);
                        } catch (NumberFormatException e) {
                            log.warn("Invalid dataAccessDuration value: {}", dataAccessDuration);
                        }
                    } else {
                        // For "all" data access, use a large number or special handling
                        // You might want to use a very large number like 365 days * 10 years
                        int maxDurationSeconds = 365 * 10 * 24 * 60 * 60; // 10 years
                        putPayload.put("dataAccessValidityDuration", maxDurationSeconds);
                        log.info("Set data access validity duration to maximum: {} seconds (all data)", 
                                maxDurationSeconds);
                    }
                }

                boolean updateSuccess = updateConsent(consentId, putPayload, getServletContext());
                
                if (updateSuccess) {
                    log.info("Successfully updated consent with ID: {}", consentId);
                } else {
                    log.error("Failed to update consent with ID: {}", consentId);
                }

            } catch (Exception e) {
                log.error("Error updating consent status for consent_id: {}", consentId, e);
            }
        }

        URI aTrue = null;
        try {
            aTrue = authorizeRequest("true", browserCookies, user, sessionDataKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String redirectURL = aTrue.toString();

        // Invoke authorize flow
        if (redirectURL != null) {
            response.sendRedirect(redirectURL);

        } else {
            session.invalidate();
            response.sendRedirect("retry.do?status=Error&statusMsg=Error while persisting consent");
        }

    }

    String persistConsentData(JSONObject consentData, String sessionDataKey, ServletContext servletContext) {

        String persistenceBaseURL = servletContext.getInitParameter(Constants.PERSISTENCE_BASE_URL);
        String persistenceUrl = persistenceBaseURL + Constants.SLASH + sessionDataKey;

        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpPatch dataRequest = new HttpPatch(persistenceUrl);
            dataRequest.addHeader(Constants.ACCEPT, Constants.JSON);
            dataRequest.addHeader(Constants.AUTHORIZATION, "");
            StringEntity body = new StringEntity(consentData.toString(), ContentType.APPLICATION_JSON);
            dataRequest.setEntity(body);
            HttpResponse dataResponse = client.execute(dataRequest);

            if (dataResponse.getStatusLine().getStatusCode() == HttpURLConnection.HTTP_MOVED_TEMP &&
                    dataResponse.getLastHeader(Constants.LOCATION) != null) {
                return dataResponse.getLastHeader(Constants.LOCATION).getValue();
            } else {
                String retrievalResponse = IOUtils.toString(dataResponse.getEntity().getContent(),
                        String.valueOf(StandardCharsets.UTF_8));
                JSONObject data = new JSONObject(retrievalResponse);
                String errorResponse = AuthenticationUtils.getErrorResponseForRedirectURL(data);
                if (data.has(Constants.REDIRECT_URI) && StringUtils.isNotEmpty(errorResponse)) {
                    URI errorURI = new URI(data.get(Constants.REDIRECT_URI).toString().concat(errorResponse));
                    return errorURI.toString();
                } else {
                    return null;
                }
            }
        } catch (IOException | JSONException | URISyntaxException e) {
            log.error("Exception while calling persistence endpoint", e);
            return null;
        }
    }

    /**
     * Fetch consent details from external API.
     *
     * @param consentId      the consent ID to fetch details for
     * @param servletContext servlet context
     * @return consent details JSON object
     * @throws IOException if an error occurs while fetching consent details
     */
    JSONObject fetchConsentDetails(String consentId, ServletContext servletContext) throws IOException {

        // Construct the consent API URL
        String consentApiBaseURL = servletContext.getInitParameter("ConsentAPIBaseURL");
        if (consentApiBaseURL == null || consentApiBaseURL.isEmpty()) {
            // Use default URL if not configured
            consentApiBaseURL = "http://localhost:3000/api/v1/consents/";
        }
        String consentApiUrl = consentApiBaseURL + consentId;

        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpGet consentRequest = new HttpGet(consentApiUrl);

        // Add required headers
        String orgId = servletContext.getInitParameter("ConsentAPI.OrgId");
        String clientId = servletContext.getInitParameter("ConsentAPI.ClientId");

        consentRequest.addHeader("org-id", orgId != null ? orgId : "org1");
        consentRequest.addHeader("client-id", clientId != null ? clientId : "string");
        consentRequest.addHeader("Accept", Constants.JSON);

        HttpResponse consentResponse = client.execute(consentRequest);

        // Parse and return the response
        if (consentResponse.getStatusLine().getStatusCode() == HttpURLConnection.HTTP_OK) {
            String responseBody = IOUtils.toString(consentResponse.getEntity().getContent(),
                    String.valueOf(StandardCharsets.UTF_8));
            return new JSONObject(responseBody);
        } else {
            log.error("Failed to fetch consent details. Status code: " +
                    consentResponse.getStatusLine().getStatusCode());
            return null;
        }
    }

    /**
     * Update consent details via external API.
     *
     * @param consentId      the consent ID to update
     * @param updatedConsent the updated consent data
     * @param servletContext servlet context
     * @return true if update was successful, false otherwise
     */
    boolean updateConsent(String consentId, JSONObject updatedConsent, ServletContext servletContext) {

        // Construct the consent API URL
        String consentApiBaseURL = servletContext.getInitParameter("ConsentAPIBaseURL");
        if (consentApiBaseURL == null || consentApiBaseURL.isEmpty()) {
            // Use default URL if not configured
            consentApiBaseURL = "http://localhost:3000/api/v1/consents/";
        }
        String consentApiUrl = consentApiBaseURL + consentId;

        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpPut updateRequest = new HttpPut(consentApiUrl);

            // Add required headers
            String orgId = servletContext.getInitParameter("ConsentAPI.OrgId");
            String clientId = servletContext.getInitParameter("ConsentAPI.ClientId");

            updateRequest.addHeader("org-id", orgId != null ? orgId : "org1");
            updateRequest.addHeader("client-id", clientId != null ? clientId : "string");
            updateRequest.addHeader("Content-Type", Constants.JSON);
            updateRequest.addHeader("Accept", Constants.JSON);

            // Set the request body
            StringEntity body = new StringEntity(updatedConsent.toString(), ContentType.APPLICATION_JSON);
            updateRequest.setEntity(body);

            // Execute the request
            HttpResponse consentResponse = client.execute(updateRequest);
            int statusCode = consentResponse.getStatusLine().getStatusCode();

            if (statusCode == HttpURLConnection.HTTP_OK || statusCode == HttpURLConnection.HTTP_CREATED) {
                String responseBody = IOUtils.toString(consentResponse.getEntity().getContent(),
                        String.valueOf(StandardCharsets.UTF_8));
                log.debug("Update consent response: {}", responseBody);
                return true;
            } else {
                log.error("Failed to update consent. Status code: {}", statusCode);
                String errorBody = IOUtils.toString(consentResponse.getEntity().getContent(),
                        String.valueOf(StandardCharsets.UTF_8));
                log.error("Error response: {}", errorBody);
                return false;
            }
        } catch (IOException e) {
            log.error("Error updating consent for consent_id: {}", consentId, e);
            return false;
        }
    }

    public static URI authorizeRequest(String consent, Map<String, String> cookies, String user, String sessionDataKey)
            throws Exception {

        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {

            BasicCookieStore cookieStore = new BasicCookieStore();
            String cookieDomain = new URI("https://localhost:9443/oauth2/authorize").getHost();
            for (Map.Entry<String, String> cookieValue : cookies.entrySet()) {
                BasicClientCookie cookie = new BasicClientCookie(cookieValue.getKey(), cookieValue.getValue());
                cookie.setDomain(cookieDomain);
                cookie.setPath("/");
                cookie.setSecure(true);
                cookieStore.addCookie(cookie);
            }
            HttpPost authorizeRequest = new HttpPost("https://localhost:9443/oauth2/authorize");
            List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("hasApprovedAlways", "false"));
            params.add(new BasicNameValuePair("sessionDataKeyConsent",
                    sessionDataKey));
            params.add(new BasicNameValuePair("consent", consent));
            params.add(new BasicNameValuePair("user", user));
            HttpContext localContext = new BasicHttpContext();
            localContext.setAttribute("http.cookie-store", cookieStore);
            UrlEncodedFormEntity entity = new UrlEncodedFormEntity(params);
            authorizeRequest.setEntity(entity);
            HttpResponse authorizeResponse = client.execute(authorizeRequest, localContext);

            if (authorizeResponse.getStatusLine().getStatusCode() != 302) {
                throw new Exception("Error while sending authorize request to complete the authorize flow");
            } else {
                // Extract the location header from the authorization redirect
                return new URI(authorizeResponse.getLastHeader("Location").getValue());
            }
        } catch (IOException e) {
            log.error("Error while sending authorize request to complete the authorize flow", e);
            throw new Exception("Error while sending authorize request to complete the authorize flow");
        } catch (URISyntaxException e) {
            log.error("Authorize response URI syntax error", e);
            throw new Exception("Authorize response URI syntax error");
        }
    }

}


