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

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
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
import org.wso2.financial.services.accelerator.authentication.endpoint.util.Constants;
import org.wso2.financial.services.accelerator.authentication.endpoint.util.LocalCacheUtil;

import javax.servlet.ServletContext;
import javax.servlet.http.*;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * The servlet responsible for the confirm page in auth web flow.
 */
public class FSConsentConfirmServlet extends HttpServlet {

    private static final long serialVersionUID = 6106269597832678046L;
    private static Logger log = LoggerFactory.getLogger(FSConsentConfirmServlet.class);

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String sessionDataKey = request.getParameter(Constants.SESSION_DATA_KEY_CONSENT);
        HttpSession session = request.getSession();
        LocalCacheUtil cache = LocalCacheUtil.getInstance();
        JSONObject cachedDataSet = cache.get(sessionDataKey, JSONObject.class);
        Map<String, String> browserCookies = new HashMap<>();
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            browserCookies.put(cookie.getName(), cookie.getValue());
        }
        String dataAccessDuration = request.getParameter("dataAccessDuration");
        String consentExpiry = request.getParameter("consentExpiry");
        String[] approvedPurposes = request.getParameterValues("accounts");
        JSONObject approvedPurposesJson = new JSONObject();
        approvedPurposesJson.put("approved_purposes", approvedPurposes);
        log.info("Approved purposes: {}", Arrays.toString(approvedPurposes));
        String user = cachedDataSet.getString("user");
        boolean approval = request.getParameter("consent") != null &&
                request.getParameter("consent").equals("true");

        String consentId = null;

        // Only create consent if user approved
        if (approval && cachedDataSet.has("validPurposes")) {
            log.info("User approved - creating consent with all data");

            try {
                // Get commonAuthId from cookies
                String commonAuthId = null;
                for (Cookie cookie : cookies) {
                    if ("commonAuthId".equals(cookie.getName())) {
                        commonAuthId = cookie.getValue();
                        log.info("Found commonAuthId cookie: {}", commonAuthId);
                        break;
                    }
                }

                // Calculate validityTime and dataAccessValidityDuration
                Long validityTime = null;
                if (consentExpiry != null && !consentExpiry.isEmpty()) {
                    try {
                        int expiryDays = Integer.parseInt(consentExpiry);
                        long currentTimestamp = System.currentTimeMillis() ;
                        long expirySeconds = (long) expiryDays * 24 * 60 * 60 * 1000;
                        validityTime = currentTimestamp + expirySeconds;
                        log.info("Set consent validity time to timestamp: {} (expires in {} days)",
                                validityTime, expiryDays);
                    } catch (NumberFormatException e) {
                        log.warn("Invalid consentExpiry value: {}", consentExpiry);
                    }
                }

                Integer dataAccessValidityDuration = null;
                if (dataAccessDuration != null && !dataAccessDuration.isEmpty()) {
                    if (!"all".equals(dataAccessDuration)) {
                        try {
                            int durationDays = Integer.parseInt(dataAccessDuration);
                            dataAccessValidityDuration = durationDays * 24 * 60 * 60;
                            log.info("Set data access validity duration to: {} seconds ({} days)",
                                    dataAccessValidityDuration, durationDays);
                        } catch (NumberFormatException e) {
                            log.warn("Invalid dataAccessDuration value: {}", dataAccessDuration);
                        }
                    } else {
                        dataAccessValidityDuration = 365 * 10 * 24 * 60 * 60; // 10 years
                        log.info("Set data access validity duration to maximum: {} seconds (all data)",
                                dataAccessValidityDuration);
                    }
                }

                // Create consent with all data including authorization
                JSONObject createdConsent = createConsentWithAuthorization(
                        approvedPurposes,
                        user,
                        commonAuthId,
                        validityTime,
                        dataAccessValidityDuration,
                        approvedPurposesJson,
                        cachedDataSet,
                        getServletContext()
                );

                if (createdConsent != null) {
                    consentId = createdConsent.optString("id", null);
                    if (consentId == null || consentId.isEmpty()) {
                        consentId = createdConsent.optString("_id",
                                createdConsent.optString("consentId", null));
                    }
                    log.info("Successfully created and authorized consent with ID: {}", consentId);
                } else {
                    log.error("Failed to create consent");
                    response.sendRedirect("retry.do?status=Error&statusMsg=consent_creation_failed");
                    return;
                }
            } catch (Exception e) {
                log.error("Error creating consent", e);
                response.sendRedirect("retry.do?status=Error&statusMsg=consent_creation_error");
                return;
            }
        } else if (!approval) {
            log.info("User denied consent");
        } else {
            log.warn("No validPurposes found in cache - cannot create consent");
            response.sendRedirect("retry.do?status=Error&statusMsg=no_valid_purposes");
            return;
        }

        URI authorizeRequestRedirect = null;
        try {
            authorizeRequestRedirect = authorizeRequest("true", browserCookies, user, sessionDataKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String redirectURL = authorizeRequestRedirect.toString();

        // Invoke authorize flow
        if (redirectURL != null) {
            response.sendRedirect(redirectURL);

        } else {
            session.invalidate();
            response.sendRedirect("retry.do?status=Error&statusMsg=Error while persisting consent");
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
        String consentApiBaseURL = "http://localhost:3000/api/v1/consents/";
        String consentApiUrl = consentApiBaseURL + consentId;
        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpGet consentRequest = new HttpGet(consentApiUrl);
        String orgId = "org1";
        String clientId = "clientId1";
        consentRequest.addHeader("org-id", orgId);
        consentRequest.addHeader("client-id", clientId);
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
        String consentApiBaseURL = "http://localhost:3000/api/v1/consents/";
        String consentApiUrl = consentApiBaseURL + consentId;
        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpPut updateRequest = new HttpPut(consentApiUrl);

            // Add required headers
            String orgId = "org1";
            String clientId = "clientId1";
            updateRequest.addHeader("org-id", orgId);
            updateRequest.addHeader("client-id", clientId);
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

    /**
     * Create a new consent with authorization in a single API call.
     *
     * @param approvedPurposes             the purposes approved by user
     * @param userId                       the user ID
     * @param commonAuthId                 the commonAuthId from cookie
     * @param validityTime                 consent expiry timestamp (can be null)
     * @param dataAccessValidityDuration   data access duration in seconds (can be null)
     * @param approvedPurposesJson         approved purposes JSON object
     * @param sessionData                  session data
     * @param servletContext               servlet context
     * @return created consent JSON object
     * @throws IOException if an error occurs
     */
    private JSONObject createConsentWithAuthorization(String[] approvedPurposes, String userId,
                                                      String commonAuthId, Long validityTime,
                                                      Integer dataAccessValidityDuration,
                                                      JSONObject approvedPurposesJson,
                                                      JSONObject sessionData, ServletContext servletContext)
            throws IOException {

        String consentApiBaseURL = "http://localhost:3000/api/v1/consents";
        consentApiBaseURL = consentApiBaseURL.replaceAll("/$", "");

        // Create HTTP client
        CloseableHttpClient client = HttpClientBuilder.create()
                .setRedirectStrategy(new org.apache.http.impl.client.LaxRedirectStrategy())
                .build();
        HttpPost consentRequest = new HttpPost(consentApiBaseURL);

        // Add required headers
        String orgId = "org1";
        String clientId = sessionData.optString("application", "clientId1");

        consentRequest.addHeader("org-id", orgId);
        consentRequest.addHeader("tpp-client-id", clientId);
        consentRequest.addHeader("Content-Type", "application/json");
        consentRequest.addHeader("Accept", "application/json");

        // Create the full consent creation request with authorization
        JSONObject consentCreationRequest = new JSONObject();
        consentCreationRequest.put("type", "accounts");
        consentCreationRequest.put("status", "ACTIVE");

        // Add validityTime (default to 0 if not provided)
        consentCreationRequest.put("validityTime", validityTime != null ? validityTime : 0);

        consentCreationRequest.put("recurringIndicator", false);

        // Add dataAccessValidityDuration (default to 86400 seconds = 1 day if not provided)
        consentCreationRequest.put("dataAccessValidityDuration",
                dataAccessValidityDuration != null ? dataAccessValidityDuration : 86400);

        consentCreationRequest.put("frequency", 0);

        JSONArray validPurposesArray = sessionData.getJSONArray("validPurposes");
        // Build consentPurpose array
        JSONArray consentPurposeArray = new JSONArray();
        for (int i = 0; i < validPurposesArray.length(); i++) {
            JSONObject purposeObj = new JSONObject();
            purposeObj.put("name", validPurposesArray.get(i));
            purposeObj.put("value", validPurposesArray.get(i));
            consentPurposeArray.put(purposeObj);
        }
        consentCreationRequest.put("consentPurpose", consentPurposeArray);

        // Add attributes with commonAuthId
        JSONObject attributes = new JSONObject();
        if (commonAuthId != null) {
            attributes.put("commonAuthId", commonAuthId);
        }
        consentCreationRequest.put("attributes", attributes);

        // Add authorizations array with approved purpose details
        JSONArray authorizationsArray = new JSONArray();
        JSONObject authorization = new JSONObject();
        authorization.put("userId", userId);
        authorization.put("type", "authorisation");
        authorization.put("status", "active");

        // Build approvedPurposeDetails
        JSONObject approvedPurposeDetails = new JSONObject();
        JSONArray approvedPurposesNames = new JSONArray();
        for (String purpose : approvedPurposes) {
            approvedPurposesNames.put(purpose);
        }
        approvedPurposeDetails.put("approvedPurposesNames", approvedPurposesNames);
        authorization.put("approvedPurposeDetails", approvedPurposeDetails);

        authorizationsArray.put(authorization);
        consentCreationRequest.put("authorizations", authorizationsArray);

        // Set request entity
        StringEntity entity = new StringEntity(consentCreationRequest.toString(), StandardCharsets.UTF_8);
        consentRequest.setEntity(entity);

        log.info("Creating consent with authorization at URL: " + consentApiBaseURL);
        log.debug("Request payload: " + consentCreationRequest.toString());

        HttpResponse consentResponse = client.execute(consentRequest);
        int statusCode = consentResponse.getStatusLine().getStatusCode();

        // Read response body
        String responseBody = "";
        if (consentResponse.getEntity() != null) {
            responseBody = IOUtils.toString(consentResponse.getEntity().getContent(),
                    String.valueOf(StandardCharsets.UTF_8));
        }

        log.info("Consent creation response - Status: " + statusCode + ", Body: " + responseBody);

        client.close();

        if (statusCode == HttpURLConnection.HTTP_OK || statusCode == HttpURLConnection.HTTP_CREATED) {
            if (!responseBody.isEmpty()) {
                try {
                    return new JSONObject(responseBody);
                } catch (JSONException e) {
                    log.error("Failed to parse consent response as JSON: " + responseBody, e);
                    return null;
                }
            }
        }

        log.error("Failed to create consent. Status: " + statusCode + ", Response: " + responseBody);
        return null;
    }

    public static URI authorizeRequest(String consent, Map<String, String> cookies, String user, String sessionDataKey)
            throws Exception {

        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {

            BasicCookieStore cookieStore = new BasicCookieStore();
            String cookieDomain = new URI("https://localhost:9446/oauth2/authorize").getHost();
            for (Map.Entry<String, String> cookieValue : cookies.entrySet()) {
                BasicClientCookie cookie = new BasicClientCookie(cookieValue.getKey(), cookieValue.getValue());
                cookie.setDomain(cookieDomain);
                cookie.setPath("/");
                cookie.setSecure(true);
                cookieStore.addCookie(cookie);
            }
            HttpPost authorizeRequest = new HttpPost("https://localhost:9446/oauth2/authorize");
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


