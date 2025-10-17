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

package com.wso2.consent.accelerator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.HybridResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;

import java.util.Arrays;

/**
 * Custom extension of HybridResponseTypeHandler.
 */
public class ConsentHybridResponseTypeHandler extends HybridResponseTypeHandler {

    private static final Log log = LogFactory.getLog(ConsentHybridResponseTypeHandler.class);

    /**
     * Custom implementation of issue method.
     *
     * @param oauthAuthzMsgCtx OAuthAuthzReqMessageContext
     * @return OAuth2AuthorizeRespDTO
     * @throws IdentityOAuth2Exception If an error occurred while issuing the code.
     */
    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Custom HybridResponseTypeHandler invoked for client: "
                    + oauthAuthzMsgCtx.getAuthorizationReqDTO().getConsumerKey());
        }


        // Perform FS default behaviour
        String[] updatedApprovedScopes = updateApprovedScopes(oauthAuthzMsgCtx);


        if (updatedApprovedScopes != null) {
            oauthAuthzMsgCtx.setApprovedScope(updatedApprovedScopes);
        }
        // Add your custom logic here before calling super.issue()

        // Call the parent implementation
        OAuth2AuthorizeRespDTO respDTO = super.issue(oauthAuthzMsgCtx);

        // Add your custom logic here after calling super.issue()

        return respDTO;
    }

    public static String[] updateApprovedScopes(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) {

        if (oAuthAuthzReqMessageContext != null && oAuthAuthzReqMessageContext.getAuthorizationReqDTO() != null) {

            String[] scopes = oAuthAuthzReqMessageContext.getApprovedScope();
            if (scopes != null && !Arrays.asList(scopes).contains("api_store")) {

                // Extract consent ID from essential claims
                String consentId = extractConsentIdFromEssentialClaims(oAuthAuthzReqMessageContext);

                if (StringUtils.isEmpty(consentId)) {
                    log.warn("Consent-ID retrieved from request is empty");
                    return scopes;
                }

                String consentIdClaim = "consent_id_";
                String consentScope = consentIdClaim + consentId;
                if (!Arrays.asList(scopes).contains(consentScope)) {
                    String[] updatedScopes = ArrayUtils.addAll(scopes, consentScope);
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("Updated scopes: %s", Arrays.toString(updatedScopes)
                                .replaceAll("[\r\n]", "")));
                    }
                    return updatedScopes;
                }
            }

        } else {
            return new String[0];
        }

        return oAuthAuthzReqMessageContext.getApprovedScope();
    }

    /**
     * Extract consent ID from essential claims in the authorization request.
     * Expected format: {"id_token":{"openbanking_intent_id":{"value":"CONSENT-xxx","essential":true}}}
     *
     * @param oAuthAuthzReqMessageContext OAuth authorization request message context
     * @return Consent ID or empty string if not found
     */
    private static String extractConsentIdFromEssentialClaims(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) {

        try {
            String essentialClaims = oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getEssentialClaims();

            if (StringUtils.isEmpty(essentialClaims)) {
                if (log.isDebugEnabled()) {
                    log.debug("Essential claims not found in the authorization request");
                }
                return "";
            }

            if (log.isDebugEnabled()) {
                log.debug("Essential claims: " + essentialClaims.replaceAll("[\r\n]", ""));
            }

            // Parse the JSON to extract consent ID
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode rootNode = objectMapper.readTree(essentialClaims);

            // Navigate through the JSON structure: id_token -> openbanking_intent_id -> value
            JsonNode idTokenNode = rootNode.get("id_token");
            if (idTokenNode != null) {
                JsonNode intentIdNode = idTokenNode.get("openbanking_intent_id");
                if (intentIdNode != null) {
                    JsonNode valueNode = intentIdNode.get("value");
                    if (valueNode != null) {
                        String consentId = valueNode.asText();
                        if (log.isDebugEnabled()) {
                            log.debug("Extracted consent ID: " + consentId.replaceAll("[\r\n]", ""));
                        }
                        return consentId;
                    }
                }
            }

            log.warn("Consent ID not found in essential claims structure");
            return "";

        } catch (JsonProcessingException e) {
            log.error("Error parsing essential claims JSON: " + e.getMessage().replaceAll("[\r\n]", ""), e);
            return "";
        } catch (Exception e) {
            log.error("Error extracting consent ID from essential claims: " + e.getMessage().replaceAll("[\r\n]", ""), e);
            return "";
        }
    }
}
