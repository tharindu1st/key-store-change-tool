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
import java.util.List;

/**
 * Class to map keyChange.xml data source for tenants registry paths.
 * This is used to get registry paths of encrypted data.
 */
public class RegistryData {

    /**
     * Registry path for key store password.
     */
    private String registryPath;

    /**
     * Resource properties.
     */
    private List<String> propertyKeyList = new ArrayList<String>();

    /**
     * This method is used to get registry path in tenant key store.
     *
     * @return  registry path for tenant key store.
     */
    public String getRegistryPath() {
        return registryPath;
    }

    /**
     * This method is used to set registry path for tenant key store.
     *
     * @param   registryPath    registry path of tenant key store.
     */
    public void setRegistryPath(String registryPath) {
        this.registryPath = registryPath;
    }

    /**
     * This method is used to get resource property list.
     *
     * @return  property list.
     */
    public List<String> getPropertyKeyList() {
        return propertyKeyList;
    }

    /**
     * This method is used to set resource property list.
     *
     * @param propertyKeyList   property list.
     */
    public void setPropertyKeyList(List<String> propertyKeyList) {
        this.propertyKeyList = propertyKeyList;
    }
}

