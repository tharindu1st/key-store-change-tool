/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.keychange.data;

/**
 * Class to map keyChange.xml data source for tenants registry paths.
 * This is used to get registry paths of encrypted data.
 */
public class TenantData {

    /**
     * Tenant domain name.
     */
    private String tenantDomain;

    /**
     * This method is used to get tenant domain when tenant key store data changes.
     *
     * @return  tenant domain.
     */
    public String getTenantDomain() {
        return tenantDomain;
    }

    /**
     * Constructor method to which binds tenant domain for TenantData object.
     *
     * @param tenantDomain  tenant domain which is used to iterate over tenants.
     */
    public TenantData(String tenantDomain){
        this.tenantDomain = tenantDomain;
    }

}

