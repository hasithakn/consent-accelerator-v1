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

<!-- Consent Expiry Time Selector -->
<div class="padding" style="margin-top: 15px;">
    <label for="consentExpiry" style="font-weight: bold; display: block; margin-bottom: 8px;">
        Consent Valid For:
    </label>
    <select id="consentExpiry" name="consentExpiry" class="form-control" style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;">
        <option value="1">1 Day</option>
        <option value="7">1 Week</option>
        <option value="30" selected>1 Month</option>
        <option value="90">3 Months</option>
        <option value="180">6 Months</option>
        <option value="365">1 Year</option>
    </select>
    <small style="display: block; margin-top: 5px; color: #666;">
        Select how long this consent should remain valid
    </small>
</div>

<!-- Data Access Duration Selector -->
<div class="padding" style="margin-top: 15px;">
    <label for="dataAccessDuration" style="font-weight: bold; display: block; margin-bottom: 8px;">
        Historical Data Access:
    </label>
    <select id="dataAccessDuration" name="dataAccessDuration" class="form-control" style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;">
        <option value="1">Previous 1 Day</option>
        <option value="7">Previous 1 Week</option>
        <option value="30" selected>Previous 1 Month</option>
        <option value="90">Previous 3 Months</option>
        <option value="180">Previous 6 Months</option>
        <option value="365">Previous 1 Year</option>
    </select>
    <small style="display: block; margin-top: 5px; color: #666;">
        Select how far back data can be accessed
    </small>
</div>