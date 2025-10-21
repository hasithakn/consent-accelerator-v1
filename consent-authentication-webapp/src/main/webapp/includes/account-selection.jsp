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

<div class="${accountSelectorClass}">
    <c:forEach items="${consumerAccounts}" var="account" varStatus="accountIdx">
        <%-- Display checkboxes for each account if multiple account selection is allowed --%>
        <label for="<c:choose><c:when test='${not empty idSuffix}'>${account}-${idSuffix}</c:when><c:otherwise>${account}</c:otherwise></c:choose>">
            <input type="checkbox"
                id="<c:choose><c:when test='${not empty idSuffix}'>${account}-${idSuffix}</c:when><c:otherwise>${account}</c:otherwise></c:choose>"
                name="<c:choose><c:when test='${not empty idSuffix}'>accounts-${idSuffix}</c:when><c:otherwise>accounts</c:otherwise></c:choose>"
                value="${account}"
            />
            ${account}
        </label>
        <br>
    </c:forEach>
</div>
