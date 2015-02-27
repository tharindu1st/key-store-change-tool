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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class to map keyChange.xml data source tenant data.
 * This is used to get key change related data from keyChange.xml.
 */
public class KeyChangeData {

    /**
     * Tenant data list. This holds tenant related from keyChange.xml.
     */
    private List<TenantData> tenantDataList = new ArrayList<TenantData>();

    /**
     * This map is used to store configuration details of old keyStore and new keyStore which is 'oldKey' and 'newKey'.
     */
    private Map<String, ConfigData> configDataMap = new HashMap<String, ConfigData>();

    /**
     * This method is used to get tenant data list when changing the encrypted data.
     *
     * @return  list of tenant data objects.
     */
    public List<TenantData> getTenantDataList() {
        return tenantDataList;
    }

    /**
     * This method is used to sets tenant data list when changing the encrypted data.
     *
     * @param   tenantDataList  list of tenant data objects.
     */
    public void setTenantDataList(List<TenantData> tenantDataList) {
        this.tenantDataList = tenantDataList;
    }

    /**
     * This method is used to get old key and new key configuration data map.
     *
     * @return  configuration data map.
     */
    public Map<String, ConfigData> getConfigDataMap() {
        return configDataMap;
    }

    /**
     * This method is used to set old key and new key configuration data map.
     *
     * @param   configDataMap   configuration data map.
     */
    public void setConfigDataMap(Map<String, ConfigData> configDataMap) {
        this.configDataMap = configDataMap;
    }
}
