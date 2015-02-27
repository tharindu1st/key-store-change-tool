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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.service.TenantRegistryLoader;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="org.wso2.carbon.keychange" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService" cardinality="1..1"
 * policy="dynamic" bind="setRegistryService" unbind="unsetRegistryService"
 * @scr.reference name="registry.core.dscomponent"
 * interface="org.wso2.carbon.registry.core.service.RegistryService" cardinality="1..1"
 * policy="dynamic" bind="setRegistryService" unbind="unsetRegistryService"
 * @scr.reference name="tenant.registryloader" interface="org.wso2.carbon.registry.core.service.TenantRegistryLoader"
 * cardinality="1..1" policy="dynamic" bind="setTenantRegistryLoader" unbind="unsetTenantRegistryLoader"
 */
public class KeyChangeServiceComponent {

    /**
     * Variable used to log entries.
     */
    private static final Log log = LogFactory.getLog(KeyChangeServiceComponent.class);

    /**
     * Method to activate bundle.
     * @param   context     OSGi component context.
     */
    protected void activate(ComponentContext context) {
        DecryptAndEncrypt decryptAndEncrypt = new DecryptAndEncrypt();
        //Decrypt and encrypt property data
        try {
            decryptAndEncrypt.decryptAndEncryptData();
            log.info("Key change bundle activated successfully");
            // Throwable exception is catch here to avoid sending any kind of exceptions including runtime exceptions
            // to OSGi framework.
        } catch (Throwable e) {
            log.error("Key store change recovery failed.", e);
        }
    }

    /**
     * Method to deactivate bundle.
     *
     * @param   context     OSGi component context.
     */
    protected void deactivate(ComponentContext context) {
        log.info("Key change bundle is deactivated");
    }

    /**
     * Method to set registry service.
     *
     * @param   registryService service to get tenant data.
     */
    protected void setRegistryService(RegistryService registryService) {
        ServiceHolder.setRegistryService(registryService);

    }

    /**
     * Method to unset registry service.
     *
     * @param   registryService service to get registry data.
     */
    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Unset Registry service");
        }
        ServiceHolder.unsetRegistryService();
    }

    /**
     * Method to set realm service.
     *
     * @param   realmService    service to get tenant data.
     */
    protected void setRealmService(RealmService realmService) {
        ServiceHolder.setRealmService(realmService);

    }

    /**
     * Method to unset realm service.
     *
     * @param   realmService    service to get tenant data.
     */
    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Unset Realm service");
        }
        ServiceHolder.unsetRealmService();
    }

    /**
     * Method to set tenant registry loader.
     *
     * @param   tenantRegLoader tenant registry loader
     */
    protected void setTenantRegistryLoader(TenantRegistryLoader tenantRegLoader) {
        ServiceHolder.setTenantRegLoader(tenantRegLoader);
    }

    /**
     * Method to unset tenant registry loader.
     *
     * @param   tenantRegLoader tenant registry loader
     */
    protected void unsetTenantRegistryLoader(TenantRegistryLoader tenantRegLoader) {
        if (log.isDebugEnabled()) {
            log.debug("Unset Tenant Registry Loader");
        }
        ServiceHolder.unsetTenantRegLoader();
    }

}
