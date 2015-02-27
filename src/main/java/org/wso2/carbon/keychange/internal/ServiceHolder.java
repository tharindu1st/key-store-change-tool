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

package org.wso2.carbon.keychange.internal;

import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.service.TenantRegistryLoader;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * This class holds the service holder to get services.
 * Registry service is called through this Service holder.
 * Realm service is called through this Service holder.
 */
public class ServiceHolder {

    /**
     * Registry service which is used to get registry data.
     */
    private static RegistryService registryService;

    /**
     * Realm Service which is used to get tenant data.
     */
    private static RealmService realmService;

    /**
     * Tenant registry loader used to load tenant data.
     */
    private static TenantRegistryLoader tenantRegLoader;

    /**
     * Method to get registry service.
     *
     * @return  registry service.
     */
    public static RegistryService getRegistryService() {
        return registryService;
    }

    /**
     * Method to set registry RegistryService.
     *
     * @param   service registry service.
     */
    public static void setRegistryService(RegistryService service) {
        registryService = service;
    }

    /**
     * Method to unset registry RegistryService.
     */
    public static void unsetRegistryService() {
        registryService = null;
    }

    /**
     * This method used to get realm service.
     *
     * @return  realm service.
     */
    public static RealmService getRealmService() {
        return realmService;
    }

    /**
     * Method to set registry realm service.
     *
     * @param   service realm service.
     */
    public static void setRealmService(RealmService service) {
        realmService = service;
    }

    /**
     * Method to unset registry realm service.
     */
    public static void unsetRealmService() {
        realmService = null;
    }

    /**
     * This method used to get TenantRegistryLoader.
     *
     * @return  tenant registry loader for load tenant registry.
     */
    public static TenantRegistryLoader getTenantRegLoader() {
        return tenantRegLoader;
    }

    /**
     * This method used to set TenantRegistryLoader.
     *
     * @param   service tenant registry loader for load tenant registry.
     */
    public static void setTenantRegLoader(TenantRegistryLoader service) {
        tenantRegLoader = service;
    }

    /**
     * This method used to unset TenantRegistryLoader.
     */
    public static void unsetTenantRegLoader() {
        tenantRegLoader = null;
    }
}

