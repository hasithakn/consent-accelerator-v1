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

<c:if test="${not empty basicConsentData}">
<%--    <c:forEach items="${basicConsentData}" var="record">--%>
        <div class="padding" style="border:1px solid #555;">
            <b>${basicConsentData}</b>
        </div>
<%--    </c:forEach>--%>
</c:if>

<c:if test="${not empty expirationTime}">
    <%--    <c:forEach items="${basicConsentData}" var="record">--%>
    <div class="padding" style="border:1px solid #555;">
        <h5>Expiration Time:</h5>
        <b>${expirationTime}</b>
    </div>
    <%--    </c:forEach>--%>
</c:if>
