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
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.financial.services.accelerator.authentication.endpoint.util.AuthenticationUtils;
import org.wso2.financial.services.accelerator.authentication.endpoint.util.Constants;
import org.wso2.financial.services.accelerator.authentication.endpoint.util.LocalCacheUtil;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.*;


/**
 * The servlet responsible for displaying the consent details in the auth UI
 * flow.
 */
public class FSConsentServlet extends HttpServlet {

    private static final long serialVersionUID = 6106269076132678046L;
    private static Logger log = LoggerFactory.getLogger(FSConsentServlet.class);

    @SuppressFBWarnings({"REQUESTDISPATCHER_FILE_DISCLOSURE", "TRUST_BOUNDARY_VIOLATION"})
    // Suppressed content - obAuthServlet.getJSPPath()
    // Suppression reason - False Positive : JSP path is hard coded and does not
    // accept any user inputs, therefore it
    // can be trusted
    // Suppressed content - Encode.forJava(sessionDataKey)
    // Suppression reason - False positive : sessionDataKey is encoded for Java
    // which escapes untrusted characters
    // Suppressed warning count - 2
    @Override
    public void doGet(HttpServletRequest originalRequest, HttpServletResponse response)
            throws IOException, ServletException {

        String sessionDataKey = originalRequest.getParameter(Constants.SESSION_DATA_KEY_CONSENT);

        // Validating session data key format
        if (!isValidSessionDataKey(sessionDataKey)) {
            log.error("Invalid session data key");
            originalRequest.getSession().invalidate();
            response.sendRedirect("retry.do?status=Error&statusMsg=Invalid session data key");
            return;
        }

        HttpResponse consentDataResponse = getConsentDataWithKey(sessionDataKey, getServletContext());
        log.debug("HTTP response for consent retrieval: " + consentDataResponse.toString());

        // Handle redirect response
        if (shouldRedirect(consentDataResponse)) {
            response.sendRedirect(consentDataResponse.getLastHeader(Constants.LOCATION).getValue());
            return;
        }

        try {
            // Parse session data from response
            JSONObject sessionData = parseSessionData(consentDataResponse);
            String user = sessionData.getString("loggedInUser");

            // Determine flow based on request parameter presence
            String requestObject = extractRequestParameter(sessionData);
            JSONObject dataSet;

            if (requestObject != null && !requestObject.isEmpty()) {
                // Flow 1: Handle JWT request parameter flow
                log.info("Processing JWT request parameter flow");
                dataSet = handleJwtRequestFlow(sessionData, requestObject, consentDataResponse.getStatusLine().getStatusCode(), response);
            } else {
                // Flow 2: Handle standard consent flow (without JWT request)
                log.info("Processing standard consent flow");
                dataSet = handleStandardConsentFlow(sessionData, consentDataResponse.getStatusLine().getStatusCode(), response);
            }

            // Check for errors
            if (dataSet == null || dataSet.has(Constants.IS_ERROR)) {
                handleError(originalRequest, response, dataSet);
                return;
            }

            // Prepare and forward to JSP
            prepareAndForwardToJSP(originalRequest, response, sessionDataKey, dataSet, user);

        } catch (Exception e) {
            log.error("Exception occurred while processing consent", e);
            handleError(originalRequest, response,
                new JSONObject().put(Constants.IS_ERROR, "Exception occurred: " + e.getMessage()));
        }
    }

    /**
     * Validates the session data key format.
     *
     * @param sessionDataKey the session data key to validate
     * @return true if valid, false otherwise
     */
    private boolean isValidSessionDataKey(String sessionDataKey) {
        try {
            UUID.fromString(sessionDataKey);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Checks if the response requires a redirect.
     *
     * @param response the HTTP response
     * @return true if redirect is needed
     */
    private boolean shouldRedirect(HttpResponse response) {
        return response.getStatusLine().getStatusCode() == HttpURLConnection.HTTP_MOVED_TEMP &&
               response.getLastHeader(Constants.LOCATION) != null;
    }

    /**
     * Parses session data from the HTTP response.
     *
     * @param consentDataResponse the HTTP response containing session data
     * @return parsed JSONObject
     * @throws IOException if parsing fails
     */
    private JSONObject parseSessionData(HttpResponse consentDataResponse) throws IOException {
        String retrievalResponse = IOUtils.toString(consentDataResponse.getEntity().getContent(),
                String.valueOf(StandardCharsets.UTF_8));
        return new JSONObject(retrievalResponse);
    }

    /**
     * Extracts the request parameter from spQueryParams.
     *
     * @param sessionData the session data JSON object
     * @return the request parameter value, or null if not found
     */
    private String extractRequestParameter(JSONObject sessionData) {
        if (!sessionData.has("spQueryParams")) {
            return null;
        }

        String spQueryParams = sessionData.getString("spQueryParams");
        String[] params = spQueryParams.split("&");

        for (String param : params) {
            if (param.startsWith("request=")) {
                try {
                    String requestObject = param.substring("request=".length());
                    // URL decode the request object
                    requestObject = java.net.URLDecoder.decode(requestObject, StandardCharsets.UTF_8.toString());
                    log.debug("Extracted request object: " + requestObject);
                    return requestObject;
                } catch (Exception e) {
                    log.error("Error extracting request parameter", e);
                    return null;
                }
            }
        }
        return null;
    }

    /**
     * Handles the JWT request parameter flow.
     *
     * @param sessionData the session data
     * @param requestObject the JWT request object
     * @param statusCode the HTTP status code
     * @param response the HTTP response
     * @return the processed consent dataset
     * @throws IOException if processing fails
     * @throws URISyntaxException if URI construction fails
     */
    private JSONObject handleJwtRequestFlow(JSONObject sessionData, String requestObject,
                                           int statusCode, HttpServletResponse response)
            throws IOException, URISyntaxException {

        // Extract consent ID from JWT
        String consentId = extractConsentIdFromJwt(requestObject);

        if (consentId == null || consentId.isEmpty()) {
            log.warn("No consent ID found in JWT request object");
            return createConsentDataset(sessionData, statusCode);
        }

        log.info("Extracted consent_id from request object: " + consentId);

        // Fetch and process consent details
        JSONObject consentDetails = fetchConsentDetails(consentId, getServletContext());

        if (consentDetails == null) {
            log.error("Failed to fetch consent details for consent_id: " + consentId);
            return new JSONObject().put(Constants.IS_ERROR, "Failed to fetch consent details");
        }

        // Validate consent status
        if (!consentDetails.getString("status").equalsIgnoreCase("CREATED")) {
            response.sendRedirect("retry.do?status=Error&statusMsg=invalid_consent_status");
            return null;
        }

        // Transform and merge consent data
        JSONObject transformedConsentData = transformConsentDetails(consentDetails, sessionData);
        if (transformedConsentData != null) {
            transformedConsentData.put("consent_id", consentId);
            mergeConsentData(sessionData, transformedConsentData);
            log.debug("Transformed consent data: " + transformedConsentData.toString());
        }

        // Check for error redirects
        String errorResponse = AuthenticationUtils.getErrorResponseForRedirectURL(sessionData);
        if (sessionData.has(Constants.REDIRECT_URI) && StringUtils.isNotEmpty(errorResponse)) {
            URI errorURI = new URI(sessionData.get(Constants.REDIRECT_URI).toString().concat(errorResponse));
            response.sendRedirect(errorURI.toString());
            return null;
        }

        return createConsentDataset(transformedConsentData, statusCode);
    }

    /**
     * Handles the standard consent flow (without JWT request parameter).
     *
     * @param sessionData the session data
     * @param statusCode the HTTP status code
     * @param response the HTTP response
     * @return the processed consent dataset
     * @throws IOException if processing fails
     * @throws URISyntaxException if URI construction fails
     */
    private JSONObject handleStandardConsentFlow(JSONObject sessionData, int statusCode,
                                                 HttpServletResponse response)
            throws IOException, URISyntaxException {

        // Debug: Log available fields in sessionData
        log.debug("Standard flow - Available session data keys: " + sessionData.keys().toString());

        // Extract purpose strings from scopes (use optString to avoid exception if missing)
        String scopesString = sessionData.optString("scopes", "");

        if (scopesString.isEmpty()) {
            log.warn("No scopes found in session data, attempting to retrieve from spQueryParams");
            // Try to extract scopes from spQueryParams if available
            if (sessionData.has("spQueryParams")) {
                String spQueryParams = sessionData.getString("spQueryParams");
                // Parse query params for scope parameter
                String[] params = spQueryParams.split("&");
                for (String param : params) {
                    if (param.startsWith("scope=")) {
                        scopesString = java.net.URLDecoder.decode(param.substring(6), "UTF-8");
                        log.debug("Extracted scopes from spQueryParams: " + scopesString);
                        break;
                    }
                }
            }
        }

        String[] purposeStrings = extractPurposesFromScopes(scopesString);

        if (purposeStrings == null || purposeStrings.length == 0) {
            log.warn("No purpose strings found in session data, creating default consent dataset");
            return createConsentDataset(sessionData, statusCode);
        }

        log.info("Extracted purpose strings from session data: " + Arrays.toString(purposeStrings));

        // Create consent instead of fetching
        JSONObject consentDetails = createConsent(purposeStrings, sessionData, getServletContext());

        if (consentDetails == null) {
            log.error("Failed to create consent");
            return new JSONObject().put(Constants.IS_ERROR, "Failed to create consent");
        }

        // Extract the created consent ID
        String consentId = consentDetails.optString("consentId", null);
        if (consentId == null || consentId.isEmpty()) {
            log.error("Consent created but no consent ID returned");
            return new JSONObject().put(Constants.IS_ERROR, "Failed to retrieve consent ID");
        }

        log.info("Successfully created consent with ID: " + consentId);

        // Validate consent status
        if (!consentDetails.getString("status").equalsIgnoreCase("CREATED")) {
            response.sendRedirect("retry.do?status=Error&statusMsg=invalid_consent_status");
            return null;
        }

        // Transform and merge consent data
        JSONObject transformedConsentData = transformConsentDetails(consentDetails, sessionData);
        if (transformedConsentData != null) {
            transformedConsentData.put("consent_id", consentId);
            mergeConsentData(sessionData, transformedConsentData);
            log.debug("Transformed consent data: " + transformedConsentData.toString());
        }

        // Check for error redirects
        String errorResponse = AuthenticationUtils.getErrorResponseForRedirectURL(sessionData);
        if (sessionData.has(Constants.REDIRECT_URI) && StringUtils.isNotEmpty(errorResponse)) {
            URI errorURI = new URI(sessionData.get(Constants.REDIRECT_URI).toString().concat(errorResponse));
            response.sendRedirect(errorURI.toString());
            return null;
        }

        return createConsentDataset(transformedConsentData, statusCode);
    }

    /**
     * Extracts consent ID from JWT request object.
     *
     * @param requestObject the JWT request object
     * @return the consent ID, or null if not found
     */
    private String extractConsentIdFromJwt(String requestObject) {
        try {
            // JWT has three parts separated by dots: header.payload.signature
            String[] jwtParts = requestObject.split("\\.");
            if (jwtParts.length < 2) {
                log.warn("Invalid JWT format");
                return null;
            }

            // Decode the payload (second part)
            String payload = new String(Base64.getUrlDecoder().decode(jwtParts[1]), StandardCharsets.UTF_8);
            log.debug("Decoded JWT payload: " + payload);

            JSONObject jwtPayload = new JSONObject(payload);

            // Extract consent_id from claims.id_token.openbanking_intent_id.value
            if (jwtPayload.has("claims")) {
                JSONObject claims = jwtPayload.getJSONObject("claims");
                if (claims.has("id_token")) {
                    JSONObject idToken = claims.getJSONObject("id_token");
                    if (idToken.has("openbanking_intent_id")) {
                        JSONObject intentId = idToken.getJSONObject("openbanking_intent_id");
                        if (intentId.has("value")) {
                            return intentId.getString("value");
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error decoding JWT request object", e);
        }
        return null;
    }

    /**
     * Merges transformed consent data into session data.
     *
     * @param sessionData the original session data
     * @param transformedConsentData the transformed consent data to merge
     */
    private void mergeConsentData(JSONObject sessionData, JSONObject transformedConsentData) {
        if (transformedConsentData == null) {
            return;
        }

        if (transformedConsentData.has("consentData")) {
            sessionData.put("consentData", transformedConsentData.get("consentData"));
        }
        if (transformedConsentData.has("consumerData")) {
            sessionData.put("consumerData", transformedConsentData.get("consumerData"));
        }
        if (transformedConsentData.has("type")) {
            sessionData.put("type", transformedConsentData.get("type"));
        }
    }

    /**
     * Handles error scenarios and redirects appropriately.
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param dataSet the dataset containing error information
     * @throws IOException if redirect fails
     */
    private void handleError(HttpServletRequest request, HttpServletResponse response,
                            JSONObject dataSet) throws IOException {
        String errorMessage = "Unknown error";

        if (dataSet != null && dataSet.has(Constants.IS_ERROR)) {
            errorMessage = dataSet.getString(Constants.IS_ERROR);
        }

        request.getSession().invalidate();
        response.sendRedirect("retry.do?status=Error&statusMsg=" + errorMessage);
    }

    /**
     * Prepares request attributes and forwards to JSP.
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param sessionDataKey the session data key
     * @param dataSet the consent dataset
     * @param user the logged-in user
     * @throws ServletException if forwarding fails
     * @throws IOException if forwarding fails
     */
    private void prepareAndForwardToJSP(HttpServletRequest request, HttpServletResponse response,
                                       String sessionDataKey, JSONObject dataSet, String user)
            throws ServletException, IOException {

        // Set variables to session
        HttpSession session = request.getSession();
        session.setAttribute(Constants.SESSION_DATA_KEY_CONSENT, Encode.forJava(sessionDataKey));
        session.setAttribute(Constants.DISPLAY_SCOPES,
                Boolean.parseBoolean(getServletContext().getInitParameter(Constants.DISPLAY_SCOPES)));

        // Set strings to request
        request.setAttribute(Constants.PRIVACY_DESCRIPTION, Constants.PRIVACY_DESCRIPTION_KEY);
        request.setAttribute(Constants.PRIVACY_GENERAL, Constants.PRIVACY_GENERAL_KEY);
        request.setAttribute(Constants.OK, Constants.OK);
        request.setAttribute(Constants.REQUESTED_SCOPES, Constants.REQUESTED_SCOPES_KEY);
        request.setAttribute(Constants.APP, dataSet.getString(Constants.APPLICATION));

        // Pass custom values to JSP
        List<String> accountsData = addAccList(dataSet);
        String applicationName = dataSet.getString(Constants.APPLICATION);
        request.setAttribute("basicConsentData", applicationName + " application is requesting your consent to access the following data: ");
        request.setAttribute("user", user);
        request.setAttribute("consumerAccounts", accountsData);

        // Add user to dataset
        dataSet.put("user", user);

        // Store dataSet in cache with sessionDataKey as the key
        LocalCacheUtil cache = LocalCacheUtil.getInstance();
        cache.put(sessionDataKey, dataSet);
        log.info("Stored dataSet in cache with key: {}", sessionDataKey);

        // Forward to JSP
        RequestDispatcher dispatcher = this.getServletContext().getRequestDispatcher("/fs_default.jsp");
        dispatcher.forward(request, response);
    }

    private static List<String> addAccList(JSONObject dataSet) {
        List<String> accountData = new ArrayList<>();
        // add accounts list
        JSONArray accountsList = dataSet.getJSONObject("consumerData").getJSONArray("accounts");
        for (int accountIndex = 0; accountIndex < accountsList.length(); accountIndex++) {
            JSONObject object = accountsList.getJSONObject(accountIndex);
            String displayName = object.getString("displayName");
            accountData.add(displayName);
        }
        return accountData;
    }

    /**
     * Retrieve consent data with the session data key from Asgardeo API.
     *
     * @param sessionDataKeyConsent session data key
     * @param servletContext        servlet context
     * @return HTTP response
     * @throws IOException if an error occurs while retrieving consent data
     */
    HttpResponse getConsentDataWithKey(String sessionDataKeyConsent, ServletContext servletContext) throws IOException {

        // Construct Asgardeo API URL
        String asgardeoBaseURL = "https://localhost:9443/api/identity/auth/v1.1/data/OauthConsentKey/";
        String retrieveUrl = asgardeoBaseURL + sessionDataKeyConsent;

        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpGet dataRequest = new HttpGet(retrieveUrl);

        // Add required headers
        dataRequest.addHeader("accept", Constants.JSON);
        dataRequest.addHeader(Constants.AUTHORIZATION, "Basic YWRtaW46YWRtaW4=");

        return client.execute(dataRequest);

    }

    /**
     * Create consent data from the response of the consent retrieval.
     *
     * @param consentResponse consent response from retrieval
     * @param statusCode      status code of the response
     * @return consent data JSON object
     * @throws IOException if an error occurs while creating the consent data
     */
    JSONObject createConsentDataset(JSONObject consentResponse, int statusCode) throws IOException {

        JSONObject errorObject = new JSONObject();
        if (statusCode != HttpURLConnection.HTTP_OK) {
            if (statusCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
                if (consentResponse.has(Constants.DESCRIPTION)) {
                    errorObject.put(Constants.IS_ERROR, consentResponse.get(Constants.DESCRIPTION));
                }
            } else {
                errorObject.put(Constants.IS_ERROR, "Retrieving consent data failed");
            }
            return errorObject;
        } else {
            return consentResponse;
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
     * Create a new consent via external API.
     *
     * @param purposeStrings the purposes/permissions for the consent
     * @param sessionData    the session data containing app and user info
     * @param servletContext servlet context
     * @return created consent details JSON object
     * @throws IOException if an error occurs while creating consent
     */
    JSONObject createConsent(String[] purposeStrings, JSONObject sessionData, ServletContext servletContext)
            throws IOException {

        // Construct the consent API URL (without trailing slash to avoid 307 redirect)
        String consentApiBaseURL = servletContext.getInitParameter("ConsentAPIBaseURL");
        if (consentApiBaseURL == null || consentApiBaseURL.isEmpty()) {
            // Use default URL if not configured
            consentApiBaseURL = "http://localhost:3000/api/v1/consents";
        }
        // Remove trailing slash if present
        consentApiBaseURL = consentApiBaseURL.replaceAll("/$", "");

        // Create HTTP client that follows redirects
        CloseableHttpClient client = HttpClientBuilder.create()
                .setRedirectStrategy(new org.apache.http.impl.client.LaxRedirectStrategy())
                .build();
        org.apache.http.client.methods.HttpPost consentRequest =
            new org.apache.http.client.methods.HttpPost(consentApiBaseURL);

        // Add required headers
        String orgId = servletContext.getInitParameter("ConsentAPI.OrgId");
        String clientId = sessionData.optString("application",
                            servletContext.getInitParameter("ConsentAPI.ClientId"));
        String userId = sessionData.optString("loggedInUser", "user");

        consentRequest.addHeader("org-id", orgId != null ? orgId : "org1");
        consentRequest.addHeader("client-id", clientId != null ? clientId : "string");
        consentRequest.addHeader("Content-Type", "application/json");
        consentRequest.addHeader("Accept", "application/json");

        // Build request payload
        JSONObject requestPayload = new JSONObject();
        JSONObject data = new JSONObject();

        // Add permissions from purpose strings
        JSONArray permissions = new JSONArray();
        for (String purpose : purposeStrings) {
            permissions.put(purpose);
        }
        data.put("Permissions", permissions);

        requestPayload.put("Data", data);

        // Create the full consent creation request
        JSONObject consentCreationRequest = new JSONObject();
        consentCreationRequest.put("type", "gov");
        consentCreationRequest.put("clientId", clientId);
        consentCreationRequest.put("userId", userId);
        consentCreationRequest.put("requestPayload", requestPayload);
        consentCreationRequest.put("status", "CREATED");

        // Set request entity
        org.apache.http.entity.StringEntity entity = new org.apache.http.entity.StringEntity(
                consentCreationRequest.toString(), StandardCharsets.UTF_8);
        consentRequest.setEntity(entity);

        log.info("Creating consent at URL: " + consentApiBaseURL);
        log.info("Request payload: " + consentCreationRequest.toString());

        HttpResponse consentResponse = client.execute(consentRequest);

        // Parse and return the response
        int statusCode = consentResponse.getStatusLine().getStatusCode();

        // Read response body
        String responseBody = "";
        if (consentResponse.getEntity() != null) {
            responseBody = IOUtils.toString(consentResponse.getEntity().getContent(),
                    String.valueOf(StandardCharsets.UTF_8));
        }

        log.info("Consent creation response - Status: " + statusCode +
                 ", Reason: " + consentResponse.getStatusLine().getReasonPhrase() +
                 ", Body length: " + responseBody.length());

        if (statusCode == HttpURLConnection.HTTP_OK || statusCode == HttpURLConnection.HTTP_CREATED) {
            if (responseBody.isEmpty()) {
                log.error("Consent creation returned success but empty response body");
                return null;
            }

            try {
                JSONObject createdConsent = new JSONObject(responseBody);
                log.info("Successfully created consent. Response keys: " + createdConsent.keys().toString());
                log.info("Full response: " + responseBody);

                // Normalize the consent ID field name
                // API might return 'id', '_id', or 'consentId'
                if (!createdConsent.has("consentId")) {
                    if (createdConsent.has("_id")) {
                        createdConsent.put("consentId", createdConsent.getString("_id"));
                        log.info("Normalized '_id' to 'consentId': " + createdConsent.getString("_id"));
                    } else if (createdConsent.has("id")) {
                        createdConsent.put("consentId", createdConsent.getString("id"));
                        log.info("Normalized 'id' to 'consentId': " + createdConsent.getString("id"));
                    } else {
                        log.warn("Response does not contain any consent ID field (_id, id, or consentId)");
                    }
                }

                return createdConsent;
            } catch (JSONException e) {
                log.error("Failed to parse consent response as JSON: " + responseBody, e);
                return null;
            }
        } else if (statusCode == HttpURLConnection.HTTP_MOVED_TEMP || statusCode == 307) {
            // Handle redirect - log the location header
            String location = consentResponse.getFirstHeader("Location") != null ?
                             consentResponse.getFirstHeader("Location").getValue() : "no location header";
            log.warn("Consent creation returned redirect (307). Location: " + location);
            log.warn("Response body: " + responseBody);

            // If there's a response body with consent info, try to use it
            if (!responseBody.isEmpty()) {
                try {
                    JSONObject redirectResponse = new JSONObject(responseBody);
                    log.info("Redirect response contains data: " + redirectResponse.keys().toString());
                    return redirectResponse;
                } catch (JSONException e) {
                    log.error("Redirect response is not valid JSON: " + responseBody);
                }
            }
            return null;
        } else {
            log.error("Failed to create consent. Status code: " + statusCode +
                     ", Reason: " + consentResponse.getStatusLine().getReasonPhrase() +
                     ", Response: " + responseBody);
            return null;
        }
    }

    /**
     * Transform consent details from external API format to required format.
     *
     * @param consentDetails the consent details from external API
     * @param sessionData    the original data object containing application info
     * @return transformed consent data JSON object
     */
    JSONObject transformConsentDetails(JSONObject consentDetails, JSONObject sessionData) {
        try {
            JSONObject result = new JSONObject();

            // Get type from consent details (e.g., "accounts", "gov")
            String consentType = consentDetails.optString("type", "gov");
            result.put("type", consentType);

            // Build consentData object
            JSONObject consentData = new JSONObject();
            consentData.put("initiatedAccountsForConsent", new org.json.JSONArray());
            consentData.put("allowMultipleAccounts", true);
            consentData.put("isReauthorization", false);
            consentData.put("additionalProperties", new JSONObject());
            consentData.put("type", consentType);

            // Build basicConsentData
            JSONObject basicConsentData = new JSONObject();
            if (consentDetails.has("requestPayload")) {
                JSONObject requestPayload = consentDetails.getJSONObject("requestPayload");
                if (requestPayload.has("Data")) {
                    JSONObject requestData = requestPayload.getJSONObject("Data");

                    // Extract ExpirationDateTime
                    if (requestData.has("ExpirationDateTime")) {
                        org.json.JSONArray expirationArray = new org.json.JSONArray();
                        expirationArray.put(requestData.getString("ExpirationDateTime"));
                        basicConsentData.put("Expiration Date Time", expirationArray);
                    }
                }
            }
            consentData.put("basicConsentData", basicConsentData);

            // Add attributes if available
            if (consentDetails.has("attributes")) {
                consentData.put("additionalProperties", consentDetails.getJSONObject("attributes"));
            }

            result.put("consentData", consentData);

            // Build consumerData object
            JSONObject consumerData = new JSONObject();
            org.json.JSONArray accountsArray = new org.json.JSONArray();

            // Extract permissions and map to accounts
            if (consentDetails.has("requestPayload")) {
                JSONObject requestPayload = consentDetails.getJSONObject("requestPayload");
                if (requestPayload.has("Data")) {
                    JSONObject requestData = requestPayload.getJSONObject("Data");

                    if (requestData.has("Permissions")) {
                        org.json.JSONArray permissions = requestData.getJSONArray("Permissions");
                        for (int i = 0; i < permissions.length(); i++) {
                            String permission = permissions.getString(i);
                            if (!permission.equalsIgnoreCase("gov")) {
                                JSONObject account = new JSONObject();
                                account.put("accountId", permission); // Keep original permission as accountId
                                account.put("displayName", getPermissionDisplayName(permission));
                                account.put("additionalProperties", new JSONObject());
                                account.put("selected", JSONObject.NULL);
                                accountsArray.put(account);
                            }
                        }
                    }
                }
            }

            consumerData.put("accounts", accountsArray);
            consumerData.put("additionalProperties", new JSONObject());
            result.put("consumerData", consumerData);

            // Get application name from original data or use clientId from consent details
            String application = sessionData.optString("application",
                    consentDetails.optString("clientId", "TPP_APP_1"));
            result.put("application", application);

            return result;

        } catch (JSONException e) {
            log.error("Error transforming consent details", e);
            return null;
        }
    }

    /**
     * Map permission codes to user-friendly display names.
     *
     * @param permission the permission code
     * @return user-friendly display name
     */
    private String getPermissionDisplayName(String permission) {
        if (permission == null || permission.trim().isEmpty()) {
            return permission;
        }

        // Map known permissions to display names
        switch (permission.toLowerCase()) {
            case "utility:read":
                return "Utility Bills Information";
            case "license:read":
                return "Driver's License Information";
            case "tax:read":
                return "Tax Records Information";
            default:
                // For unknown permissions, convert to title case
                return formatPermissionName(permission);
        }
    }

    /**
     * Format permission name to be more readable.
     * Converts "some:permission" to "Some Permission"
     *
     * @param permission the permission code
     * @return formatted permission name
     */
    private String formatPermissionName(String permission) {
        if (permission == null || permission.trim().isEmpty()) {
            return permission;
        }

        // Remove common suffixes like :read, :write, :delete
        String cleanedPermission = permission.replaceAll(":(read|write|delete|update|create)", "");

        // Replace common separators with spaces
        cleanedPermission = cleanedPermission.replaceAll("[_:\\-.]", " ");

        // Capitalize first letter of each word
        String[] words = cleanedPermission.split("\\s+");
        StringBuilder result = new StringBuilder();
        for (String word : words) {
            if (word.length() > 0) {
                result.append(Character.toUpperCase(word.charAt(0)))
                      .append(word.substring(1).toLowerCase())
                      .append(" ");
            }
        }

        return result.toString().trim();
    }

    /**
     * Extract purpose strings from scopes.
     * Scopes may be space-separated or comma-separated.
     * Filters out common OAuth scopes (openid, profile, email, etc.)
     * and consent_id_ scopes.
     *
     * @param scopesString the scopes string (space or comma separated)
     * @return array of purpose strings
     */
    String[] extractPurposesFromScopes(String scopesString) {
        if (scopesString == null || scopesString.trim().isEmpty()) {
            return new String[0];
        }

        // Split by space or comma
        String[] scopes = scopesString.trim().split("[\\s,]+");

        // Filter out OAuth standard scopes and consent_id scopes
        java.util.List<String> purposes = new java.util.ArrayList<>();
        for (String scope : scopes) {
            scope = scope.trim();
            // Skip empty, standard OAuth scopes, and consent_id scopes
            if (!scope.isEmpty() &&
                !scope.equalsIgnoreCase("openid") &&
                !scope.equalsIgnoreCase("profile") &&
                !scope.equalsIgnoreCase("email") &&
                !scope.equalsIgnoreCase("address") &&
                !scope.equalsIgnoreCase("phone") &&
                !scope.startsWith("consent_id_")) {
                purposes.add(scope);
            }
        }

        return purposes.toArray(new String[0]);
    }
}
