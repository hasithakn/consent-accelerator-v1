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

    @Override
    public void doGet(HttpServletRequest originalRequest, HttpServletResponse response)
            throws IOException {

        String sessionDataKey = originalRequest.getParameter(Constants.SESSION_DATA_KEY_CONSENT);
        HttpResponse consentDataResponse = getConsentDataWithKey(sessionDataKey);
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
            JSONObject dataSet;
            dataSet = handleStandardConsentFlow(sessionData, consentDataResponse.getStatusLine().getStatusCode(),
                    response);

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
     * Handles the standard consent flow
     *
     * @param sessionData the session data
     * @param statusCode  the HTTP status code
     * @param response    the HTTP response
     * @return the processed consent dataset
     * @throws IOException        if processing fails
     * @throws URISyntaxException if URI construction fails
     */
    private JSONObject handleStandardConsentFlow(JSONObject sessionData, int statusCode,
                                                 HttpServletResponse response)
            throws IOException, URISyntaxException {

        String[] purposeStrings = null;

        // First, try to extract purposes from request object if present
        if (sessionData.has("spQueryParams")) {
            String spQueryParams = sessionData.getString("spQueryParams");
            purposeStrings = extractPurposesFromRequestObject(spQueryParams);
            
            if (purposeStrings != null && purposeStrings.length > 0) {
                log.info("Extracted {} purpose(s) from request object: {}", 
                        purposeStrings.length, Arrays.toString(purposeStrings));
            }
        }

        // If no purposes found in request object, fall back to extracting from scopes
        if (purposeStrings == null || purposeStrings.length == 0) {
            log.debug("No purposes found in request object, attempting to extract from scopes");
            
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
            purposeStrings = extractPurposesFromScopes(scopesString);
            
            if (purposeStrings != null && purposeStrings.length > 0) {
                log.info("Extracted {} purpose(s) from scopes: {}", 
                        purposeStrings.length, Arrays.toString(purposeStrings));
            }
        }

        // If still no purposes found, create default consent dataset
        if (purposeStrings == null || purposeStrings.length == 0) {
            log.warn("No purpose strings found in request object or scopes, returning session data");
            return sessionData;
        }

        // Validate the extracted purposes and get back the valid ones
        String[] validPurposes = validateConsentPurposes(purposeStrings, getServletContext());
        if (validPurposes == null || validPurposes.length == 0) {
            log.error("Consent purposes validation failed for: " + Arrays.toString(purposeStrings));
            return new JSONObject().put(Constants.IS_ERROR, "Invalid consent purposes");
        }
        log.info("Consent purposes validated successfully. Valid purposes: " + Arrays.toString(validPurposes));

        // Store valid purposes in sessionData for later use in consent confirmation
        JSONArray validPurposesArray = new JSONArray();
        for (String purpose : validPurposes) {
            validPurposesArray.put(purpose);
        }


        



        sessionData.put("validPurposes", validPurposesArray);

        // Check for error redirects
        String errorResponse = AuthenticationUtils.getErrorResponseForRedirectURL(sessionData);
        if (sessionData.has(Constants.REDIRECT_URI) && StringUtils.isNotEmpty(errorResponse)) {
            URI errorURI = new URI(sessionData.get(Constants.REDIRECT_URI).toString().concat(errorResponse));
            response.sendRedirect(errorURI.toString());
            return null;
        }

        return sessionData;
    }

    /**
     * Handles error scenarios and redirects appropriately.
     *
     * @param request  the HTTP request
     * @param response the HTTP response
     * @param dataSet  the dataset containing error information
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
     * @param request        the HTTP request
     * @param response       the HTTP response
     * @param sessionDataKey the session data key
     * @param dataSet        the consent dataset
     * @param user           the logged-in user
     * @throws ServletException if forwarding fails
     * @throws IOException      if forwarding fails
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
        List<Map<String, String>> purposeData = addPurposeList(dataSet);
        String applicationName = dataSet.getString(Constants.APPLICATION);
        request.setAttribute("basicConsentData", applicationName +
                " application is requesting your consent to access the following data: ");
        request.setAttribute("user", user);
        request.setAttribute("consumerAccounts", purposeData);

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

    private List<Map<String, String>> addPurposeList(JSONObject dataSet) {
        List<Map<String, String>> purposeDataMap = new ArrayList<>();

        // Extract valid purposes from validPurposes array
        if (dataSet.has("validPurposes")) {
            JSONArray validPurposes = dataSet.getJSONArray("validPurposes");
            for (int i = 0; i < validPurposes.length(); i++) {
                String purpose = validPurposes.getString(i);
                if (!purpose.equalsIgnoreCase("gov")) {
                    Map<String, String> purposeMap = new HashMap<>();
                    purposeMap.put("value", purpose); // This will be the checkbox value
                    purposeMap.put("label", getPermissionDisplayName(purpose)); // This will be displayed in UI
                    purposeDataMap.add(purposeMap);
                }
            }
        } else {
            log.warn("No validPurposes found in dataSet, returning empty purpose list");
        }
        
        return purposeDataMap;
    }

    /**
     * Retrieve consent data with the session data key from Asgardeo API.
     *
     * @param sessionDataKeyConsent session data key
     * @return HTTP response
     * @throws IOException if an error occurs while retrieving consent data
     */
    HttpResponse getConsentDataWithKey(String sessionDataKeyConsent) throws IOException {

        // Construct IS API URL
        String isBaseURL = "https://localhost:9446/api/identity/auth/v1.1/data/OauthConsentKey/";
        String retrieveUrl = isBaseURL + sessionDataKeyConsent;
        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpGet dataRequest = new HttpGet(retrieveUrl);
        dataRequest.addHeader("accept", Constants.JSON);
        dataRequest.addHeader(Constants.AUTHORIZATION, "Basic YWRtaW46YWRtaW4=");
        return client.execute(dataRequest);

    }
    
    /**
     * Validate consent purposes using the external validation API.
     *
     * @param purposeStrings the purposes to validate
     * @param servletContext servlet context
     * @return array of valid purposes, or null if validation fails
     */
    String[] validateConsentPurposes(String[] purposeStrings, ServletContext servletContext) {
        if (purposeStrings == null || purposeStrings.length == 0) {
            log.warn("No purposes to validate");
            return null;
        }

        try {
            // Construct the validation API URL
            String validationApiUrl = "http://localhost:3000/api/v1/consent-purposes/validate";

            // Create HTTP client
            CloseableHttpClient client = HttpClientBuilder.create()
                    .setRedirectStrategy(new org.apache.http.impl.client.LaxRedirectStrategy())
                    .build();
            org.apache.http.client.methods.HttpPost validationRequest =
                    new org.apache.http.client.methods.HttpPost(validationApiUrl);

            // Add required headers
            validationRequest.addHeader("org-id", "org1");
            validationRequest.addHeader("Content-Type", "application/json");
            validationRequest.addHeader("Accept", "application/json");

            // Build JSON array payload from purposeStrings
            JSONArray purposesArray = new JSONArray();
            for (String purpose : purposeStrings) {
                purposesArray.put(purpose);
            }

            // Set request entity
            org.apache.http.entity.StringEntity entity = new org.apache.http.entity.StringEntity(
                    purposesArray.toString(), StandardCharsets.UTF_8);
            validationRequest.setEntity(entity);

            log.info("Validating consent purposes at URL: " + validationApiUrl);
            log.debug("Validation payload: " + purposesArray.toString());

            HttpResponse validationResponse = client.execute(validationRequest);
            int statusCode = validationResponse.getStatusLine().getStatusCode();

            // Read response body
            String responseBody = "";
            if (validationResponse.getEntity() != null) {
                responseBody = IOUtils.toString(validationResponse.getEntity().getContent(),
                        String.valueOf(StandardCharsets.UTF_8));
            }

            log.info("Validation response - Status: " + statusCode +
                    ", Body: " + responseBody);

            client.close();

            // Check if validation was successful (200 OK)
            if (statusCode == HttpURLConnection.HTTP_OK) {
                // Response should be a JSON array of valid purposes: ["utility_read", "license_read"]
                try {
                    JSONArray validPurposesArray = new JSONArray(responseBody);
                    
                    if (validPurposesArray.length() > 0) {
                        // Convert JSONArray to String[]
                        String[] validPurposes = new String[validPurposesArray.length()];
                        for (int i = 0; i < validPurposesArray.length(); i++) {
                            validPurposes[i] = validPurposesArray.getString(i);
                        }
                        
                        log.info("Validation successful. Valid purposes count: " + validPurposes.length);
                        log.debug("Valid purposes: " + Arrays.toString(validPurposes));
                        return validPurposes;
                    } else {
                        log.warn("Validation returned empty array - no valid purposes found");
                        return null;
                    }
                } catch (JSONException e) {
                    log.error("Failed to parse validation response as JSON array: " + responseBody, e);
                    return null;
                }
            } else {
                // Error response format: {"code": "BAD_REQUEST", "message": "Invalid request", "details": "no valid purposes found"}
                try {
                    JSONObject errorResponse = new JSONObject(responseBody);
                    String errorCode = errorResponse.optString("code", "UNKNOWN");
                    String errorMessage = errorResponse.optString("message", "Validation failed");
                    String errorDetails = errorResponse.optString("details", "");
                    
                    log.error("Validation failed - Code: " + errorCode + 
                            ", Message: " + errorMessage + 
                            ", Details: " + errorDetails);
                } catch (JSONException e) {
                    log.error("Validation failed with status: " + statusCode + 
                            ", Response: " + responseBody);
                }
                return null;
            }

        } catch (Exception e) {
            log.error("Error validating consent purposes: " + Arrays.toString(purposeStrings), e);
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

        String consentApiBaseURL =  "http://localhost:3000/api/v1/consents";
        consentApiBaseURL = consentApiBaseURL.replaceAll("/$", "");

        CloseableHttpClient client = HttpClientBuilder.create()
                .setRedirectStrategy(new org.apache.http.impl.client.LaxRedirectStrategy()).build();
        org.apache.http.client.methods.HttpPost consentRequest =
                new org.apache.http.client.methods.HttpPost(consentApiBaseURL);

        // Add required headers
        String orgId = "org1";
        String clientId = "clientId1";
        consentRequest.addHeader("org-id", orgId);
        consentRequest.addHeader("client-id", clientId);
        consentRequest.addHeader("Content-Type", "application/json");
        consentRequest.addHeader("Accept", "application/json");
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
        consentCreationRequest.put("requestPayload", requestPayload);
        consentCreationRequest.put("status", "CREATED");

        // Set request entity
        org.apache.http.entity.StringEntity entity = new org.apache.http.entity.StringEntity(
                consentCreationRequest.toString(), StandardCharsets.UTF_8);
        consentRequest.setEntity(entity);
        HttpResponse consentResponse = client.execute(consentRequest);
        int statusCode = consentResponse.getStatusLine().getStatusCode();

        String responseBody = "";
        if (consentResponse.getEntity() != null) {
            responseBody = IOUtils.toString(consentResponse.getEntity().getContent(),
                    String.valueOf(StandardCharsets.UTF_8));
        }
        if (statusCode == HttpURLConnection.HTTP_OK || statusCode == HttpURLConnection.HTTP_CREATED) {
            if (responseBody.isEmpty()) {
                log.error("Consent creation returned success but empty response body");
                return null;
            }
            try {
                JSONObject createdConsent = new JSONObject(responseBody);
                log.info("Successfully created consent. Response keys: " + createdConsent.keys().toString());
                log.info("Full response: " + responseBody);
                return createdConsent;
            } catch (JSONException e) {
                log.error("Failed to parse consent response as JSON: " + responseBody, e);
                return null;
            }
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
     * Handles both colon-separated (utility:read) and underscore-separated (utility_read) formats.
     *
     * @param permission the permission code
     * @return user-friendly display name
     */
    private String getPermissionDisplayName(String permission) {
        if (permission == null || permission.trim().isEmpty()) {
            return permission;
        }

        // Normalize the permission string to lowercase for comparison
        String normalizedPermission = permission.toLowerCase();

        // Map known permissions to display names (supporting both : and _ separators)
        switch (normalizedPermission) {
            case "utility:read":
            case "utility_read":
                return "Utility Bills Information";
            case "license:read":
            case "license_read":
                return "Driver's License Information";
            case "tax:read":
            case "tax_read":
                return "Tax Records Information";
            default:
                return permission;
        }
    }

    /**
     * Extract purpose strings from request object in spQueryParams.
     * The request object is a JWT that contains consent_purposes array.
     *
     * @param spQueryParams the query parameters string
     * @return array of purpose strings from request object, or empty array if not found
     */
    String[] extractPurposesFromRequestObject(String spQueryParams) {
        if (spQueryParams == null || spQueryParams.trim().isEmpty()) {
            return new String[0];
        }

        try {
            // Parse query params to find 'request' parameter
            String[] params = spQueryParams.split("&");
            String requestObjectJwt = null;
            
            for (String param : params) {
                if (param.startsWith("request=")) {
                    requestObjectJwt = java.net.URLDecoder.decode(param.substring(8), "UTF-8");
                    log.debug("Found request object parameter");
                    break;
                }
            }

            if (requestObjectJwt == null || requestObjectJwt.isEmpty()) {
                log.debug("No request object found in spQueryParams");
                return new String[0];
            }

            // Decode JWT (assuming it's a simple JWT without signature verification for now)
            // JWT format: header.payload.signature
            String[] jwtParts = requestObjectJwt.split("\\.");
            
            if (jwtParts.length < 2) {
                log.warn("Invalid JWT format in request object");
                return new String[0];
            }

            // Decode the payload (second part)
            String payloadEncoded = jwtParts[1];
            byte[] decodedBytes = java.util.Base64.getUrlDecoder().decode(payloadEncoded);
            String payloadJson = new String(decodedBytes, StandardCharsets.UTF_8);
            
            log.debug("Decoded request object payload: " + payloadJson);

            // Parse JSON payload
            JSONObject requestObject = new JSONObject(payloadJson);

            // Extract consent_purposes array
            if (requestObject.has("consent_purposes")) {
                JSONArray consentPurposes = requestObject.getJSONArray("consent_purposes");
                List<String> purposes = new ArrayList<>();
                
                for (int i = 0; i < consentPurposes.length(); i++) {
                    String purpose = consentPurposes.getString(i);
                    if (purpose != null && !purpose.trim().isEmpty()) {
                        purposes.add(purpose);
                    }
                }
                
                if (!purposes.isEmpty()) {
                    log.info("Successfully extracted {} consent purposes from request object", purposes.size());
                    return purposes.toArray(new String[0]);
                }
            } else {
                log.debug("Request object does not contain 'consent_purposes' field");
            }

        } catch (Exception e) {
            log.error("Error extracting purposes from request object", e);
        }

        return new String[0];
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
