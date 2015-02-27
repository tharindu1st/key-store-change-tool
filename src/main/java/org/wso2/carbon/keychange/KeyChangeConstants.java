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

package org.wso2.carbon.keychange;

/**
 * This class holds Constants related to key store change recovery of registry data.
 */
public final class KeyChangeConstants {

    /**
     * This parameter is defined here because it is a fixed path.
     * This is the path to where the data sources files are stored in the registry.
     */
    public static final String DSS_DATA_SOURCE_FILE_LOCATION = "/_system/config/repository/components/org.wso2.carbon"
            + ".ndatasource";

    /**
     * keyChange.xml file name.
     */
    public static final String XML_FILE = "keyChange.xml";

    /**
     * keyChange.xsd file name.
     */
    public static final String XSD_FILE = "keyChange.xsd";

    /**
     * Old key xPath.
     */
    public static final String OLD_KEY_PATH = "/KeyChange/Config/OldKey/KeyPath";

    /**
     * Old key password xPath.
     */
    public static final String OLD_KEY_PASSWORD_XPATH = "/KeyChange/Config/OldKey/KeyPass";

    /**
     * Old key alias xPath.
     */
    public static final String OLD_KEY_ALIAS_XPATH = "/KeyChange/Config/OldKey/KeyAlias";

    /**
     * New key xPath.
     */
    public static final String NEW_KEY_XPATH = "/KeyChange/Config/NewKey/KeyPath";

    /**
     * New key password xPath.
     */
    public static final String NEW_KEY_PASSWORD_XPATH = "/KeyChange/Config/NewKey/KeyPass";

    /**
     * New key alias xPath.
     */
    public static final String NEW_KEY_ALIAS_XPATH = "/KeyChange/Config/NewKey/KeyAlias";

    /**
     * Tenant domain xPath.
     */
    public static final String TENANT_DOMAIN_XPATH = "/KeyChange/TenantDomains/TenantDomain";

    /**
     * Key store changed date xPath.
     */
    public static final String KEY_CHANGE_DATE_XPATH = "/KeyChange/Config/ChangedDateTimestamp";

    /**
     * Key store changed method xPath.
     */
    public static final String KEY_CHANGE_METHOD_XPATH = "/KeyChange/Config/ChangeMethod";

    /**
     * Key store changed method xPath.
     */
    public static final String KEY_CHANGE_RESOURCE_XPATH = "KeyChange/RegistryData/Resource";

    /**
     * Key store registry xPath.
     */
    public static final String KEY_CHANGE_REGISTRY_XPATH = "RegistryPath";

    /**
     * Key store registry property xPath.
     */
    public static final String KEY_CHANGE_PROPERTY_XPATH = "PropertyKey";

    /**
     * DSS deployed selection boolean xPath.
     */
    public static final String IS_DSS_DEPLOYED_XPATH = "/KeyChange/isDssDeployed";

    /**
     * Old key, key for KeyChangeData.
     */
    public static final String OLD_KEY_MAP_KEY = "OldKey";

    /**
     * New key, key for KeyChangeData.
     */
    public static final String NEW_KEY_MAP_KEY = "NewKey";

    /**
     * Key store type used.
     */
    public static final String KEY_STORE_TYPE = "JKS";

    /**
     * Cipher text transformation type.
     */
    public static final String CIPHER_TRANSFORMATION_METHOD = "RSA";

    /**
     * Cipher provider.
     */
    public static final String CIPHER_PROVIDER = "BC";

    /**
     * Cipher operation mode constant for encryption.
     */
    public static final int OPERATION_MODE_ENCRYPTION = 1;

    /**
     * Cipher operation mode constant for decryption.
     */
    public static final int OPERATION_MODE_DECRYPTION = 2;

    /**
     * This parameter is the super admin username.
     */
    public static final String SUPER_ADMIN_USERNAME = "admin";

    /**
     * Method 'date' to key change method in KeyChange.xml file.
     */
    public static final String METHOD_DATE = "date";

    /**
     * Method 'keyChangeXML' to key change method in KeyChange.xml file.
     */
    public static final String METHOD_KEY_CHANGE_XML = "keyChangeXML";

    /**
     * Key change date format in KeyChange.xml file.
     */
    public static final String KEY_CHANGE_DATE_FORMAT = "d-MMM-yyyy,HH:mm:ss";

    /**
     * Tenant domain pattern.
     */
    public static final String TENANT_DOMAIN_PATTERN = "${tenant.domain}";

    /**
     * Tenant id pattern.
     */
    public static final String TENANT_ID_PATTERN = "${tenant.id}";

    /**
     * Constant '.' used in tenant domain pattern replace.
     */
    public static final String DOT = ".";

    /**
     * Constant '-' used in tenant domain pattern replace.
     */
    public static final String DASH = "-";

    /**
     * Constant of UTF-8.
     */
    public static final String UTF_8 = "UTF-8";

    /**
     * Constant of YES.
     */
    public static final String YES = "YES";

    /**
     * Xpath for password element in DSS data source.
     */
    public static final String XPATH_DATA_SOURCE_PASSWORD = "/datasource/definition/configuration/password";
}
