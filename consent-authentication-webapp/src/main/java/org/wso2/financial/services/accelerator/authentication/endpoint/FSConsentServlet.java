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

        HttpServletRequest request = originalRequest;
        String user = "";
        // get consent data
        String sessionDataKey = request.getParameter(Constants.SESSION_DATA_KEY_CONSENT);

        // validating session data key format
        try {
            UUID.fromString(sessionDataKey);
        } catch (IllegalArgumentException e) {
            log.error("Invalid session data key", e);
            request.getSession().invalidate();
            response.sendRedirect("retry.do?status=Error&statusMsg=Invalid session data key");
            return;
        }

        HttpResponse consentDataResponse = getConsentDataWithKey(sessionDataKey, getServletContext());
        JSONObject dataSet = new JSONObject();
        log.debug("HTTP response for consent retrieval" + consentDataResponse.toString());
        try {
            if (consentDataResponse.getStatusLine().getStatusCode() == HttpURLConnection.HTTP_MOVED_TEMP &&
                    consentDataResponse.getLastHeader(Constants.LOCATION) != null) {
                response.sendRedirect(consentDataResponse.getLastHeader(Constants.LOCATION).getValue());
                return;
            } else {
                String retrievalResponse = IOUtils.toString(consentDataResponse.getEntity().getContent(),
                        String.valueOf(StandardCharsets.UTF_8));
                JSONObject sessionData = new JSONObject(retrievalResponse);

                // get consent details
                String requestObject = null;
                String consentId = null;
                user = sessionData.getString("loggedInUser");
                if (sessionData.has("spQueryParams")) {
                    String spQueryParams = sessionData.getString("spQueryParams");
                    // Extract the request parameter from the query string
                    String[] params = spQueryParams.split("&");
                    for (String param : params) {
                        if (param.startsWith("request=")) {
                            requestObject = param.substring("request=".length());
                            // URL decode the request object
                            requestObject = java.net.URLDecoder.decode(requestObject, StandardCharsets.UTF_8.toString());
                            log.debug("Extracted request object: " + requestObject);

                            // Decode JWT to extract consent_id
                            try {
                                // JWT has three parts separated by dots: header.payload.signature
                                String[] jwtParts = requestObject.split("\\.");
                                if (jwtParts.length >= 2) {
                                    // Decode the payload (second part)
                                    String payload = new String(Base64.getUrlDecoder().decode(jwtParts[1]),
                                            StandardCharsets.UTF_8);
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
                                                    consentId = intentId.getString("value");
                                                    log.info("Extracted consent_id from request object: " + consentId);
                                                }
                                            }
                                        }
                                    }
                                }
                            } catch (Exception e) {
                                log.error("Error decoding JWT request object", e);
                            }
                            break;
                        }
                    }
                }

                // Fetch consent details from external API if consent_id is available
                JSONObject consentDetails = null;
                JSONObject transformedConsentData = null;
                if (consentId != null && !consentId.isEmpty()) {
                    try {
                        consentDetails = fetchConsentDetails(consentId, getServletContext());
                        if (consentDetails != null) {
                            log.info("Successfully fetched consent details for consent_id: " + consentId);

                            if (!consentDetails.getString("status").equalsIgnoreCase("awaitingAuthorization")) {
                                response.sendRedirect("retry.do?status=Error&statusMsg=invalid_consent_status");
                                return;
                            }
                            // Transform consent details to required format
                            transformedConsentData = transformConsentDetails(consentDetails, sessionData);
                            transformedConsentData.append("consent_id", consentId);

                            // Merge transformed consent sessionData into the main sessionData object
                            if (transformedConsentData != null) {
                                sessionData.put("consentData", transformedConsentData.get("consentData"));
                                sessionData.put("consumerData", transformedConsentData.get("consumerData"));
                                // Update type if available
                                if (transformedConsentData.has("type")) {
                                    sessionData.put("type", transformedConsentData.get("type"));
                                }
                                log.debug("Transformed consent sessionData: " + transformedConsentData.toString());
                            }
                        }
                    } catch (IOException e) {
                        log.error("Error fetching consent details for consent_id: " + consentId, e);
                        // Continue processing even if consent details fetch fails
                    }
                }


                String errorResponse = AuthenticationUtils.getErrorResponseForRedirectURL(sessionData);
                if (sessionData.has(Constants.REDIRECT_URI) && StringUtils.isNotEmpty(errorResponse)) {
                    URI errorURI = new URI(sessionData.get(Constants.REDIRECT_URI).toString().concat(errorResponse));
                    response.sendRedirect(errorURI.toString());
                    return;
                } else {
                    dataSet = createConsentDataset(transformedConsentData, consentDataResponse.getStatusLine().getStatusCode());
                }
            }
        } catch (IOException e) {
            log.error("Exception occurred while retrieving consent data", e);
            dataSet.put(Constants.IS_ERROR, "Exception occurred while retrieving consent data");
        } catch (URISyntaxException e) {
            log.error("Error while constructing URI for redirection", e);
            dataSet.put(Constants.IS_ERROR, "Error while constructing URI for redirection");
        } catch (JSONException e) {
            log.error("Error while parsing the response", e);
            dataSet.put(Constants.IS_ERROR, "Error while parsing the response");
        }
        if (dataSet.has(Constants.IS_ERROR)) {
            String isError = (String) dataSet.get(Constants.IS_ERROR);
            request.getSession().invalidate();
            response.sendRedirect("retry.do?status=Error&statusMsg=" + isError);
            return;
        }

        // set variables to session
        HttpSession session = request.getSession();

        session.setAttribute(Constants.SESSION_DATA_KEY_CONSENT, Encode.forJava(sessionDataKey));
        session.setAttribute(Constants.DISPLAY_SCOPES,
                Boolean.parseBoolean(getServletContext().getInitParameter(Constants.DISPLAY_SCOPES)));

        // set strings to request
        ResourceBundle resourceBundle = AuthenticationUtils.getResourceBundle(request.getLocale());

        originalRequest.setAttribute(Constants.PRIVACY_DESCRIPTION, Constants.PRIVACY_DESCRIPTION_KEY);
        originalRequest.setAttribute(Constants.PRIVACY_GENERAL, Constants.PRIVACY_GENERAL_KEY);

        // bottom.jsp
        originalRequest.setAttribute(Constants.OK, Constants.OK);
        originalRequest.setAttribute(Constants.REQUESTED_SCOPES, Constants.REQUESTED_SCOPES_KEY);

        originalRequest.setAttribute(Constants.APP, dataSet.getString(Constants.APPLICATION));

        // Pass custom values to JSP

        List<String> accountsData = addAccList(dataSet);
        originalRequest.setAttribute("basicConsentData", "Details of the consent:");
        originalRequest.setAttribute("user", user);
        originalRequest.setAttribute("expirationTime", dataSet.getJSONObject("consentData")
                .getJSONObject("basicConsentData").getJSONArray("Expiration Date Time").get(0));
        originalRequest.setAttribute("consumerAccounts", accountsData);
        // dispatch
        dataSet.append("user", user);

        // Store dataSet in cache with sessionDataKey as the key
        LocalCacheUtil cache = LocalCacheUtil.getInstance();
        cache.put(sessionDataKey, dataSet);
        log.info("Stored dataSet in cache with key: {}", sessionDataKey);

        RequestDispatcher dispatcher = this.getServletContext().getRequestDispatcher("/fs_default.jsp");
        dispatcher.forward(originalRequest, response);

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
                            JSONObject account = new JSONObject();
                            account.put("accountId", JSONObject.NULL);
                            account.put("displayName", permissions.getString(i));
                            account.put("additionalProperties", new JSONObject());
                            account.put("selected", JSONObject.NULL);
                            accountsArray.put(account);
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
}
