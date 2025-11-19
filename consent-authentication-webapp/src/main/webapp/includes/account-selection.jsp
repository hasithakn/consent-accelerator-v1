<%--
~ Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
~
~ WSO2 LLC. licenses this file to you under the Apache License,
~ Version 2.0 (the "License"); you may not use this file except
~ in compliance with the License.
~ You may obtain a copy of the License at
~
~     http://www.apache.org/licenses/LICENSE-2.0
~
~ Unless required by applicable law or agreed to in writing,
~ software distributed under the License is distributed on an
~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
~ KIND, either express or implied. See the License for the
~ specific language governing permissions and limitations
~ under the License.
--%>

<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix = "c" uri = "http://java.sun.com/jsp/jstl/core" %>

<c:set var="accountSelectorClass" value="${param.accountSelectorClass}" />
<c:set var="idSuffix" value="${param.idSuffix}" />
<c:set var="ignorePreSelect" value="${param.ignorePreSelect}" />

<!-- Consent Page Heading -->
<div style="margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #0078d4;">
    <h2 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 600;">
        Consent Authorization Request
    </h2>
    <p style="margin: 8px 0 0 0; color: #605e5c; font-size: 14px;">
        Review and authorize the following information access
    </p>
</div>

<!-- Application Consent Message -->
<c:if test="${not empty basicConsentData}">
<%--    <c:forEach items="${basicConsentData}" var="record">--%>
        <div class="padding" style="border:1px solid #555; margin-bottom: 15px;">
            <b>${basicConsentData}</b>
        </div>
<%--    </c:forEach>--%>
</c:if>

<div class="${accountSelectorClass}" style="margin-bottom: 25px;">
    <!-- First render pre-selected accounts (checked and disabled) -->
    <c:forEach items="${consumerAccounts}" var="account">
        <c:if test='${account.selected == "true" || account.selected eq true}'>
            <label for="<c:choose><c:when test='${not empty idSuffix}'>${account.value}-${idSuffix}</c:when><c:otherwise>${account.value}</c:otherwise></c:choose>">
                <input type="checkbox"
                    id="<c:choose><c:when test='${not empty idSuffix}'>${account.value}-${idSuffix}</c:when><c:otherwise>${account.value}</c:otherwise></c:choose>"
                    name="<c:choose><c:when test='${not empty idSuffix}'>accounts-${idSuffix}</c:when><c:otherwise>accounts</c:otherwise></c:choose>"
                    value="${account.value}"
                    checked="checked"
                    disabled="disabled"
                />
                ${account.label}
            </label>
            <!-- Preserve submitted value for disabled checkbox -->
            <input type="hidden" name="<c:choose><c:when test='${not empty idSuffix}'>accounts-${idSuffix}</c:when><c:otherwise>accounts</c:otherwise></c:choose>" value="${account.value}" />
            <br/>
        </c:if>
    </c:forEach>

    <!-- Separator between selected and unselected accounts if both groups exist -->
    <c:set var="hasSelected" value="false" />
    <c:forEach items="${consumerAccounts}" var="account">
        <c:if test='${account.selected == "true" || account.selected eq true}'>
            <c:set var="hasSelected" value="true" />
        </c:if>
    </c:forEach>

    <c:set var="hasUnselected" value="false" />
    <c:forEach items="${consumerAccounts}" var="account">
        <c:if test='${not (account.selected == "true" || account.selected eq true)}'>
            <c:set var="hasUnselected" value="true" />
        </c:if>
    </c:forEach>

    <c:if test="${hasSelected == 'true' && hasUnselected == 'true'}">
        <div style="margin: 12px 0;">
            <h4 style="margin: 6px 0; color: #333; font-size: 16px;">Optional data:</h4>
            <hr style="border: 0; border-top: 1px dashed #ccc;"/>
        </div>
    </c:if>

    <!-- Then render remaining (non-selected) accounts -->
    <c:forEach items="${consumerAccounts}" var="account">
        <c:if test='${not (account.selected == "true" || account.selected eq true)}'>
            <label for="<c:choose><c:when test='${not empty idSuffix}'>${account.value}-${idSuffix}</c:when><c:otherwise>${account.value}</c:otherwise></c:choose>">
                <input type="checkbox"
                    id="<c:choose><c:when test='${not empty idSuffix}'>${account.value}-${idSuffix}</c:when><c:otherwise>${account.value}</c:otherwise></c:choose>"
                    name="<c:choose><c:when test='${not empty idSuffix}'>accounts-${idSuffix}</c:when><c:otherwise>accounts</c:otherwise></c:choose>"
                    value="${account.value}"
                />
                ${account.label}
            </label>
            <br/>
        </c:if>
    </c:forEach>
</div>
