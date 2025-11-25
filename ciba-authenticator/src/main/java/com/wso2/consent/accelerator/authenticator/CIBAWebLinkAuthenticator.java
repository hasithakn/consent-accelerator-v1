/*
 * Copyright (c)  2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.wso2.consent.accelerator.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * CIBA Web Link Authenticator for sending auth web links to authentication device / devices
 */
public class CIBAWebLinkAuthenticator extends AbstractApplicationAuthenticator implements
        LocalApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(CIBAWebLinkAuthenticator.class);

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(request);
        String webAuthLink = generateWebAuthLink(context, authenticatedUser);
        triggerNotificationEvent(authenticatedUser.getUserName(), webAuthLink);
    }

    /**
     * Method to trigger the notification event in IS.
     */
    protected void triggerNotificationEvent(String userName, String webLink) throws AuthenticationFailedException {

        log.info("CIBAWebLinkAuthenticator triggering notification event for user: " + userName);
        log.info(webLink);
    }

    /**
     * Method to identify the user/users involved in the authentication.
     *
     * @param request HttpServletRequest
     * @return list of users
     */
    protected AuthenticatedUser getAuthenticatedUser(HttpServletRequest request)
            throws AuthenticationFailedException {

        if (request.getParameter(CIBAWebLinkAuthenticatorConstants.LOGIN_HINT) == null ||
                request.getParameter(CIBAWebLinkAuthenticatorConstants.LOGIN_HINT).isEmpty()) {
            log.error("Login hint is not present in the authentication request");
            throw new AuthenticationFailedException("Login hint is not present in the authentication request");
        }
        return AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                request.getParameter(CIBAWebLinkAuthenticatorConstants.LOGIN_HINT).trim());
    }


    /**
     * Method to generate web auth links for given user.
     *
     * @param context authentication context.
     * @param user    authenticated user.
     * @return Auth web link for authenticated user.
     */
    protected String generateWebAuthLink(AuthenticationContext context, AuthenticatedUser user)
            throws AuthenticationFailedException {

        List<String> allowedParams =
                List.of("client_id", "scope", "response_type", "nonce", "redirect_uri", "binding_message");
        List<String> paramList = Arrays.stream(context.getQueryParams().split("&")).filter(e -> {
            for (String allowedParam : allowedParams) {
                if (e.startsWith(allowedParam)) {
                    return true;
                }
            }
            return false;
        }).collect(Collectors.toList());

        // Rename `request_object` query params to `request` param.
        List<String> requestObjectList = Arrays.stream(context.getQueryParams().split("&"))
                .filter(e -> e.startsWith("request")).collect(Collectors.toList());
        String requestObject = requestObjectList.get(0).split("=")[1];
        paramList.add("request=" + requestObject);
        paramList.add(CIBAWebLinkAuthenticatorConstants.CIBA_WEB_AUTH_LINK_PARAM + "=true");
        paramList.add("login_hint=" + user.getUserName());

        StringBuilder builder = new StringBuilder();
        builder.append(IdentityUtil.getServerURL(
                CIBAWebLinkAuthenticatorConstants.AUTHORIZE_URL_PATH, false, true));
        for (String param : paramList) {
            builder.append(param).append("&");
        }
        if (log.isDebugEnabled()) {
            log.debug(builder.toString());
        }
        return builder.toString();
    }


    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        // This authenticator is used only to send the web-auth links, And it does not expect to process the response.
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        // CIBA web link Authenticator is used only to send the web-auth links, And it does not expect to handle it.
        return false;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);
    }

    @Override
    public String getName() {

        return "SampleLocalAuthenticator";
    }

    @Override
    public String getFriendlyName() {

        return "ciba-authenticator";
    }
}
