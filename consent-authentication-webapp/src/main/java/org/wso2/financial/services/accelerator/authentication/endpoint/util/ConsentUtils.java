package org.wso2.financial.services.accelerator.authentication.endpoint.util;

import java.io.IOException;
import java.net.HttpURLConnection;

import java.nio.charset.StandardCharsets;

import javax.servlet.ServletContext;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConsentUtils {

    private static Logger log = LoggerFactory.getLogger(ConsentUtils.class);
    // Common constants
    private static final String CONSENT_API_BASE_URL = "http://localhost:3000/api/v1/consents/";
    private static final String PURPOSE_GROUPS_API_BASE_URL = "http://localhost:3000/api/v1/consent-purpose-groups";
    private static final String ORG_ID = "ORG-001";
    private static final String CLIENT_ID = "TPP-CLIENT-001";

    /**
     * GET consent details from external API.
     *
     * @param consentId      the consent ID to fetch details for
     * @param servletContext servlet context
     * @return consent details JSON object
     * @throws IOException if an error occurs while fetching consent details
     */
    public static JSONObject getConsentDetails(String consentId, ServletContext servletContext) throws IOException {

        // Construct the consent API URL
        String consentApiUrl = CONSENT_API_BASE_URL + consentId;
        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpGet consentRequest = new HttpGet(consentApiUrl);
        consentRequest.addHeader("org-id", ORG_ID);
        consentRequest.addHeader("client-id", CLIENT_ID);
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
    public static JSONObject updateConsent(String consentId, JSONObject updatedConsent, ServletContext servletContext) {

        // Construct the consent API URL
        String consentApiUrl = CONSENT_API_BASE_URL + consentId;
        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpPut updateRequest = new HttpPut(consentApiUrl);

            // Add required headers
            updateRequest.addHeader("org-id", ORG_ID);
            updateRequest.addHeader("TPP-client-id", CLIENT_ID);
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
                return new JSONObject(responseBody);
            } else {
                log.error("Failed to update consent. Status code: {}", statusCode);
                String errorBody = IOUtils.toString(consentResponse.getEntity().getContent(),
                        String.valueOf(StandardCharsets.UTF_8));
                log.error("Error response: {}", errorBody);
                return null;
            }
        } catch (IOException e) {
            log.error("Error updating consent for consent_id: {}", consentId, e);
            return null;
        }
    }

    /**
     * Resolves whether a purpose is mandatory for a given purpose group.
     * Calls the consent purpose groups API to retrieve the purpose group details
     * and determines the mandatory status of the specified purpose.
     *
     * @param purposeGroupName the name of the consent purpose group
     * @param purposeName the name of the specific purpose
     * @param servletContext servlet context
     * @return Boolean true if mandatory, false if not mandatory, null if not found or error occurred
     */
    public static Boolean resolvePurposeMandatory(String purposeGroupName, String purposeName,
                                                  ServletContext servletContext) {
        if (purposeGroupName == null || purposeGroupName.trim().isEmpty() ||
            purposeName == null || purposeName.trim().isEmpty()) {
            log.warn("Purpose group name or purpose name is null or empty");
            return null;
        }

        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            // Construct the API URL with name filter
            String apiUrl = PURPOSE_GROUPS_API_BASE_URL + "?name=" +
                           java.net.URLEncoder.encode(purposeGroupName, "UTF-8");

            log.debug("Calling consent purpose groups API: {}", apiUrl);

            // Create HTTP request
            HttpGet request = new HttpGet(apiUrl);
            request.addHeader("org-id", ORG_ID);
            request.addHeader("client-id", CLIENT_ID);
            request.addHeader("Accept", Constants.JSON);

            // Execute request
            HttpResponse response = client.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();

            if (statusCode != HttpURLConnection.HTTP_OK) {
                log.error("Failed to fetch purpose groups. Status code: {}", statusCode);
                String errorBody = IOUtils.toString(response.getEntity().getContent(),
                        String.valueOf(StandardCharsets.UTF_8));
                log.error("Error response: {}", errorBody);
                return null;
            }

            // Parse response
            String responseBody = IOUtils.toString(response.getEntity().getContent(),
                                                   String.valueOf(StandardCharsets.UTF_8));
            JSONObject responseJson = new JSONObject(responseBody);

            // Extract data array
            if (!responseJson.has("data")) {
                log.warn("No 'data' field in response from purpose groups API");
                return null;
            }

            JSONArray dataArray = responseJson.getJSONArray("data");

            // Find the matching purpose group
            for (int i = 0; i < dataArray.length(); i++) {
                JSONObject group = dataArray.getJSONObject(i);

                if (purposeGroupName.equals(group.getString("name"))) {
                    // Found the matching group, now find the purpose
                    if (group.has("purposes")) {
                        JSONArray purposes = group.getJSONArray("purposes");

                        for (int j = 0; j < purposes.length(); j++) {
                            JSONObject purpose = purposes.getJSONObject(j);

                            if (purposeName.equals(purpose.getString("purposeName"))) {
                                // Found the matching purpose, return isMandatory
                                boolean isMandatory = purpose.getBoolean("isMandatory");
                                log.info("Found purpose '{}' in group '{}', isMandatory: {}",
                                        purposeName, purposeGroupName, isMandatory);
                                return isMandatory;
                            }
                        }
                    }

                    log.warn("Purpose '{}' not found in group '{}'", purposeName, purposeGroupName);
                    return null;
                }
            }

            log.warn("Purpose group '{}' not found", purposeGroupName);
            return null;

        } catch (IOException e) {
            log.error("Error calling consent purpose groups API", e);
            return null;
        } catch (JSONException e) {
            log.error("Error parsing JSON response from purpose groups API", e);
            return null;
        }
    }

}
