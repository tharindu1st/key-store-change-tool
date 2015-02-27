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
import org.w3c.dom.Document;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.keychange.KeyChangeConstants;
import org.wso2.carbon.keychange.KeyChangeException;
import org.wso2.carbon.keychange.data.ConfigData;
import org.wso2.carbon.keychange.data.KeyChangeData;
import org.wso2.carbon.keychange.data.RegistryData;
import org.wso2.carbon.keychange.data.TenantData;
import org.wso2.carbon.keychange.utils.KeyChangeCryptoUtils;
import org.wso2.carbon.keychange.utils.KeyChangeDataUtils;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.utils.RegistryUtils;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathExpressionException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * This class holds the methods to decrypt and encrypt data in tenants due to a key store change
 * Used in KeyStoreChangeServiceComponent.
 */
public class DecryptAndEncrypt {

    /**
     * Variable used to log entries.
     */
    private static final Log log = LogFactory.getLog(DecryptAndEncrypt.class);

    /**
     * Document builder used to get keyChange.xml data.
     */
    private static final DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();

    /**
     * File path to old key store.
     */
    private String oldKeyPath;

    /**
     * Old key store password.
     */
    private String oldKeyPass;

    /**
     * Old key store alias.
     */
    private String oldKeyAlias;

    /**
     * File path to new key store.
     */
    private String newKeyPath;

    /**
     * New key store password.
     */
    private String newKeyPass;

    /**
     * New key store alias.
     */
    private String newKeyAlias;

    /**
     * This method is used to set configuration data for old and new key store objects.
     *
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>"keyChange.xml validation error occurs.</li>
     *                                  <li>"keyChange.xml document element fails.</li>
     *                              </ul>
     */
    private void initialize() throws KeyChangeException {
        // Validating the xml to avoid null pointers
        if (KeyChangeDataUtils.validateXML()) {
            // Get config data from keyDataElement (keyChange.xml).
            KeyChangeData keyChangeData = KeyChangeDataUtils.getKeyChangeConfigData(getKeyChangeXmlDocument());
            ConfigData oldConfig = keyChangeData.getConfigDataMap().get(KeyChangeConstants.OLD_KEY_MAP_KEY);
            ConfigData newConfig = keyChangeData.getConfigDataMap().get(KeyChangeConstants.NEW_KEY_MAP_KEY);
            /*
             Set old config data. oldConfig can not be null because these data are taken from keyChange.xml and
             its validated through keyChange.xsd for null values.
             */
            oldKeyPath = oldConfig.getKeyPath();
            oldKeyPass = oldConfig.getKeyPass();
            oldKeyAlias = oldConfig.getKeyAlias();
            /*
             Set new config data. newConfig can not be null because these data are taken from keyChange.xml and
             its validated through keyChange.xsd for null values.
             */
            newKeyPath = newConfig.getKeyPath();
            newKeyPass = newConfig.getKeyPass();
            newKeyAlias = newConfig.getKeyAlias();
        } else {
            throw new KeyChangeException("keyChange.xml validation error when setting key store data. Please "
                    + "check your configurations");
        }
    }

    /**
     * This method is used by the service activator method to decrypt data using old key store and encrypt data using
     * new key store.
     *
     * @throws  KeyChangeException  Throws when validation error occurred while getting tenant or registry data.
     */
    public void decryptAndEncryptData() throws KeyChangeException {
        // Validating the xml to avoid null pointers
        if (KeyChangeDataUtils.validateXML()) {
            // Set key store configurations
            initialize();
            // Decrypt and encrypt resource properties using new key store.
            changeEncryptedEntries();
            // Decrypt and encrypt data for DSS
            if (KeyChangeDataUtils.isDssDeployed(getKeyChangeXmlDocument())) {
                changeDSSDataSourceEncryptedEntries();
            }
        } else {
            throw new KeyChangeException("keyChange.xml validation error when getting tenant or registry data. Please"
                    + " check your configurations");
        }
    }

    /**
     * This method is used to decrypt and encrypt tenants resource properties.
     *
     * @throws  KeyChangeException  Throws when:
*                                   <ul>
*                                       <li>KeyChangeExceptions thrown in statTenantFlow, decryptAndEncryptProperties
*                                       methods.</li>
*                                       <li>If an error occurs while getting registry from service holder
*                                       getRegistryService() method.</li>
*                                   </ul>
     */
    private void changeEncryptedEntries() throws KeyChangeException {
        List<Tenant> tenantList = getTenantList();
        // Iterate through tenants
        for (Tenant tenant : tenantList) {
            String tenantDomain = tenant.getDomain();
            String tenantAdminUsername = tenant.getAdminName();
            try {
                // Start a new tenant flow for a tenant
                int tenantId = statTenantFlow(tenantDomain, tenantAdminUsername);

                // Load tenants registry
                ServiceHolder.getTenantRegLoader().loadTenantRegistry(tenantId);
                Registry registry = ServiceHolder.getRegistryService().getRegistry(tenantAdminUsername, tenantId);

                // Get key change affected registry data.
                List<RegistryData> keyChangeRegistryData = KeyChangeDataUtils
                        .getRegistryData(getKeyChangeXmlDocument());

                // Iterate through registry resource.
                for (RegistryData registryData : keyChangeRegistryData) {
                    List<String> propertyList = registryData.getPropertyKeyList();
                    String registryPath = registryData.getRegistryPath();
                    /*
                     Replace with tenant domain if tenant domain is in resource. registryPath can not be null
                     because its taken from keyChange.xml and its validated through keyChange.xsd for null values.
                     */
                    if (registryPath.contains(KeyChangeConstants.TENANT_DOMAIN_PATTERN)) {
                        /*
                         tenantDomain can not be null because its taken from separating tenants from
                         created date and keyChange.xml. keyChange.xml tenants are validated through
                         keyChange.xsd for null values.
                         */
                        registryPath = registryPath.replace(KeyChangeConstants.TENANT_DOMAIN_PATTERN,
                                tenantDomain.replace(KeyChangeConstants.DOT, KeyChangeConstants.DASH));
                    }
                    // Replace with tenant id if tenant id is in resource
                    if (registryPath.contains(KeyChangeConstants.TENANT_ID_PATTERN)) {
                        registryPath = registryPath
                                .replace(KeyChangeConstants.TENANT_ID_PATTERN, String.valueOf(tenantId));
                    }
                    // Decrypt, encrypt and store registry properties.
                    decryptAndEncryptProperties(registry, registryPath, propertyList);
                }
            } catch (RegistryException e) {
                throw new KeyChangeException("Error while getting registry from service holder getRegistryService() "
                        + "method.", e);
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    /**
     * This method is used to decrypt and encrypt encrypted data in file. These were encrypted in wso2dss-3.1.1.
     *
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>KeyChangeExceptions thrown in statTenantFlow,
     *                                  changeDataSourcePasswordHash methods.</li>
     *                                  <li>If an error occurs while getting registry from service holder
     *                                  getRegistryService() method.</li>
     *                              </ul>
     */
    private void changeDSSDataSourceEncryptedEntries() throws KeyChangeException {
        List<Tenant> tenantList = getTenantList();
        // Iterate through tenants
        for (Tenant tenant : tenantList) {
            String tenantDomain = tenant.getDomain();
            String tenantAdminUsername = tenant.getAdminName();
            try {
                // Start a new tenant flow for a tenant
                int tenantId = statTenantFlow(tenantDomain, tenantAdminUsername);
                // Load tenants registry
                ServiceHolder.getTenantRegLoader().loadTenantRegistry(tenantId);
                Registry registry = ServiceHolder.getRegistryService().getRegistry(tenantAdminUsername, tenantId);

                if (registry.resourceExists(KeyChangeConstants.DSS_DATA_SOURCE_FILE_LOCATION)) {
                    Resource dataSourceCollectionResource = registry
                            .get(KeyChangeConstants.DSS_DATA_SOURCE_FILE_LOCATION);

                    if (dataSourceCollectionResource instanceof Collection) {

                        Collection collection = (Collection) dataSourceCollectionResource;
                        String[] dataSourceRegistryFilePaths = collection.getChildren();
                        // Iterate over data sources.
                        for (String dataSourceRegistryFilePath : dataSourceRegistryFilePaths) {
                            if (registry.resourceExists(dataSourceRegistryFilePath)) {
                                Resource resource = registry.get(dataSourceRegistryFilePath);
                                // Change DSS password hash.
                                changeDataSourcePasswordHash(registry, resource, dataSourceRegistryFilePath);
                            }
                        }
                    }
                }
            } catch (RegistryException e) {
                throw new KeyChangeException("Error while getting registry from service holder getRegistryService() "
                        + "method", e);
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    /**
     * This method is used to get tenant list for decrypting and encrypting data.
     *
     * @return tenantList           tenant list from xml file of separation by key store changed data.
     * @throws KeyChangeException   Throws when exceptions thrown in getKeyChangeMethod, getTenantsByKeyChangeDate,
     *                              getTenantsByKeyChangeXml methods.
     */
    private List<Tenant> getTenantList() throws KeyChangeException {
        List<Tenant> tenantList = new ArrayList<Tenant>();
        String tenantChangedMethod = KeyChangeDataUtils.getKeyChangeMethod(getKeyChangeXmlDocument());
        // Get tenants by separating from key change date or from keyChange.xml
        if (KeyChangeConstants.METHOD_DATE.equals(tenantChangedMethod)) {
            tenantList = getTenantsByKeyChangeDate();
        } else if (KeyChangeConstants.METHOD_KEY_CHANGE_XML.equals(tenantChangedMethod)) {
            tenantList = getTenantsByKeyChangeXml(getKeyChangeXmlDocument());
        }
        // Adding super tenant to the list
        Tenant superTenant = new Tenant();
        superTenant.setId(MultitenantConstants.SUPER_TENANT_ID);
        superTenant.setDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        superTenant.setAdminName(KeyChangeConstants.SUPER_ADMIN_USERNAME);
        superTenant.setActive(true);
        // Add super tenant to tenant list.
        tenantList.add(superTenant);
        return tenantList;
    }

    /**
     * This method is used to get tenant list for decrypting and encrypting by key store change date separation.
     *
     * @return tenantList           tenant list by separation from key store changed date.
     * @throws KeyChangeException   Throws when:
     *                              <ul>
     *                                  <li>If an error occurs while getting tenant tenants by key change date
     *                                  separation.</li>
     *                                  <li>If an date parse error occurs when getting key store change date from
     *                                  keyChange.xml.</li>
     *                              </ul>
     */
    private List<Tenant> getTenantsByKeyChangeDate() throws KeyChangeException {
        List<Tenant> tenantList = new ArrayList<Tenant>();
        String changeDate = null;
        try {
            TenantManager tenantManager = ServiceHolder.getRealmService().getTenantManager();
            Tenant[] tenantsArray = tenantManager.getAllTenants();

            changeDate = KeyChangeDataUtils.getKeyChangeDate(getKeyChangeXmlDocument());
            /*
             changeDate cannot be null because it's taken from keyChange.xml and its validate through keyChange.xsd
             for null values.
             */
            DateFormat formatter = new SimpleDateFormat(KeyChangeConstants.KEY_CHANGE_DATE_FORMAT);
            Date keyStoreChangedDate = formatter.parse(changeDate);

            for (Tenant tenantFromArray : tenantsArray) {
                // This is done because tenantAdminName is not available in tenants taken from getAllTenants
                Tenant tenant = tenantManager.getTenant(tenantFromArray.getId());
                if (tenant != null) {
                    // Get tenants which are created at the time of key change and before the key change.
                    if (tenant.getCreatedDate() != null) {
                        if (tenant.getCreatedDate().before(keyStoreChangedDate) || tenant.getCreatedDate()
                                .equals(keyStoreChangedDate)) {
                            tenantList.add(tenant);
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Tenant created date is not set for tenant id:" + tenant.getId() + ", domain:" +
                                    tenant.getDomain());
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Tenant object is null for tenant id:" + tenantFromArray.getId() + ", domain:" +
                                tenantFromArray.getDomain());
                    }
                }
            }
        } catch (UserStoreException e) {
            throw new KeyChangeException("Error while getting tenants by key change date: " + changeDate, e);
        } catch (ParseException e) {
            throw new KeyChangeException("Date parse error when getting key store change date: " + changeDate + " from "
                    + "keyChange.xml.", e);
        }
        return tenantList;
    }

    /**
     * This method is used to get tenant list for decrypting and encrypting from keyChange.xml.
     *
     * @return tenantList           tenant list from keyChange.xml file.
     * @throws KeyChangeException   Throws when a User store exception throws while getting the tenant ID for tenant
     *                              from tenant domain.
     */
    private List<Tenant> getTenantsByKeyChangeXml(Document document) throws KeyChangeException {
        List<Tenant> tenantList = new ArrayList<Tenant>();
        List<TenantData> tenantDataList;
        tenantDataList = KeyChangeDataUtils.getKeyChangeTenantDataByXML(document).getTenantDataList();
        TenantManager tenantManager = ServiceHolder.getRealmService().getTenantManager();
        // Iterate through tenants
        for (TenantData tenantData : tenantDataList) {
            String tenantDomain = null;
            try {
                tenantDomain = tenantData.getTenantDomain();
                int tenantId = ServiceHolder.getRealmService().getTenantManager().getTenantId(tenantDomain);
                if (tenantId != MultitenantConstants.INVALID_TENANT_ID) {
                    Tenant tenant = tenantManager.getTenant(tenantId);
                    tenantList.add(tenant);
                } else {
                    log.error("Invalid tenant domain '" + tenantDomain + "'");
                    // If the specific tenant domain is invalid continuing the flow for the rest of the tenants.
                }
            } catch (UserStoreException e) {
                throw new KeyChangeException("User store exception while getting the tenant ID for tenant " +
                        tenantDomain, e);
            }
        }
        return tenantList;
    }

    /**
     * This method is used to get keyChange.xml document.
     *
     * @return                      document object generated from keyChange.xml.
     * @throws KeyChangeException   Throws when:
     *                              <ul>
     *                                  <li>If ans error occurs while getting document builder.</li>
     *                                  <li>If keyChange.xml file not found.</li>
     *                                  <li>If keyChange.xml file parsing error occurs.</li>
     *                                  <li>If keyChange.xml file input error occurs while creating the file input
     *                                  stream or closing the file input stream.</li>
     *                                  <li></li>
     *                              </ul>
     */
    private Document getKeyChangeXmlDocument() throws KeyChangeException {
        DocumentBuilder builder;
        try {
            builder = builderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new KeyChangeException("Error while getting document builder.", e);
        }

        FileInputStream fileInputStream = null;
        try {
            fileInputStream = new FileInputStream(CarbonUtils.getCarbonConfigDirPath() + File.separator +
                    KeyChangeConstants.XML_FILE);
            return builder.parse(fileInputStream);
        } catch (FileNotFoundException e) {
            throw new KeyChangeException("keyChange.xml file not found.", e);
        } catch (SAXException e) {
            throw new KeyChangeException("keyChange.xml file parsing error.", e);
        } catch (IOException e) {
            throw new KeyChangeException("keyChange.xml file input error", e);
        } finally {
            try {
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
            } catch (IOException e) {
                log.error("keyChange.xml file input error", e);
            }
        }
    }

    /**
     * This method is used to call decryptAndEncryptProperty while iterating through property list.
     *
     * @param registry              registry core object.
     * @param registryPath          registry path to resource.
     * @param propertyList          property list to decrypt and encrypt entries.
     * @throws KeyChangeException   Throws when:
     *                              <ul>
     *                                  <li>If an exception occurs while encrypting and decrypting a property.</li>
     *                                  <li>If registry error occurs while accessing resource.</li>
     *                              </ul>
     */
    private void decryptAndEncryptProperties(Registry registry, String registryPath, List<String> propertyList)
            throws KeyChangeException {
        try {
            if (registry.resourceExists(registryPath)) {
                Resource resource = registry.get(registryPath);
                // Iterate through
                for (String property : propertyList) {
                    resource.setProperty(property, decryptAndEncryptProperty(resource.getProperty(property)));
                    log.info("Property '" + property + "' updated successfully in " + registryPath);
                }
                // Store the updated resource to registry.
                registry.put(registryPath, resource);
            } else {
                log.debug("Resource '" + registryPath + "' does not exists");
                // If the specific resource not found continuing the flow is OK for other resources.
                // Hence exception is not thrown.
            }
        } catch (RegistryException e) {
            throw new KeyChangeException("Registry error while accessing resource in: " + registryPath, e);
        }
    }

    /**
     *  This method is used a registry property to decrypt with old key and encrypt with new key.
     *
     * @param property              registry property to be encrypt using old key and decrypt with new key.
     * @return                      encrypted entry using new key.
     * @throws KeyChangeException   Throws when:
     *                              <ul>
     *                                  <li>KeyChangeExceptions thrown from base64DecodeAndDecrypt method while
     *                                  decrypting.</li>
     *                                  <li>KeyChangeExceptions thrown from base64DecodeAndDecrypt method while
     *                                  encrypting.</li>
     *                              </ul>
     */
    private String decryptAndEncryptProperty(String property) throws KeyChangeException {
        byte[] existingDataDecodedByteArray = KeyChangeCryptoUtils.base64DecodeAndDecrypt(property, oldKeyPath,
                oldKeyPass, oldKeyAlias);
        // Encrypt, encode and get the cipher text
        return KeyChangeCryptoUtils.encryptAndBase64Encode(existingDataDecodedByteArray, newKeyPath, newKeyPass,
                newKeyAlias);
    }

    /**
     * This method is used to tenant flow.
     *
     * @param tenantDomain          tenant domain needed to start the tenant flow.
     * @param tenantAdminUsername   tenant admin username needed to start the tenant flow.
     * @return                      tenant flow started tenant's tenant id.
     * @throws KeyChangeException   Throws when a user store exception occurs while getting the tenant ID for tenant.
     */
    private int statTenantFlow(String tenantDomain, String tenantAdminUsername) throws KeyChangeException {
        // Start a new tenant flow for a tenant
        log.info("Tenant '" + tenantDomain + "' update started.");
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        int tenantId;
        try {
            tenantId = ServiceHolder.getRealmService().getTenantManager().getTenantId(tenantDomain);
        } catch (UserStoreException e) {
            throw new KeyChangeException("User store exception while getting the tenant ID for tenant " +
                    tenantDomain, e);
        }
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(tenantAdminUsername);
        return tenantId;
    }

    /**
     * This method is used to decrypt an encrypt DSS data source password hash. Decryption is done using the old key
     * and encryption using new key.
     *
     * @param registry                      core registry
     * @param resource                      resource which contains the data source.
     * @param dataSourceRegistryFilePath    registry path to data source.
     * @throws KeyChangeException           Throws when:
     *                                      <ul>
     *                                          <li>If configurations errors occurred while trying to get document
     *                                          builder.</li>
     *                                          <li>KeyChangeExceptions thrown from getDocumentElement,
     *                                          transformDomToXml methods.</li>
     *                                          <li>XPathExpressionException if the xPath is wrong.</li>
     *                                          <li>If registry exception occurs while updating resource.</li>
     *                                          <li>UnsupportedEncodingException if DSS data source password encoding
     *                                          not supported.</li>
     *                                      </ul>
     */
    private void changeDataSourcePasswordHash(Registry registry, Resource resource, String
            dataSourceRegistryFilePath) throws KeyChangeException {

        DocumentBuilder builder;
        try {
            builder = builderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new KeyChangeException("Configuration error occurred while trying to get document builder.", e);
        }
        // Get DSS data source document element.
        Document dataSourceDocument = getDocumentElement(builder, resource);
        // Get data source password.
        String dataSourcePassword;
        try {
            dataSourcePassword = KeyChangeDataUtils
                    .getValueByXpathExpression(KeyChangeConstants.XPATH_DATA_SOURCE_PASSWORD, dataSourceDocument);
            KeyChangeDataUtils
                    .getNodeByXpathExpression(KeyChangeConstants.XPATH_DATA_SOURCE_PASSWORD, dataSourceDocument)
                    .setTextContent(decryptAndEncryptProperty(dataSourcePassword));
        } catch (XPathExpressionException e) {
            throw new KeyChangeException("Error xPath expression: " + KeyChangeConstants.XPATH_DATA_SOURCE_PASSWORD, e);
        }
        // Transform Document element to XML and set to resource content.
        try {
            resource.setContent(transformDomToXml(dataSourceDocument).getBytes(KeyChangeConstants.UTF_8));
            registry.put(dataSourceRegistryFilePath, resource);
            log.info("Data source '" + dataSourceRegistryFilePath + "' Updated successfully.");
        } catch (RegistryException e) {
            throw new KeyChangeException("Registry exception while updating resource in " +
                    dataSourceRegistryFilePath, e);
        } catch (UnsupportedEncodingException e) {
            throw new KeyChangeException("DSS data source password encoding not supported for " +
                    dataSourceRegistryFilePath, e);
        }
    }

    /**
     * This method is used to transform Document element to XML. Used to transform DOM element generated by DSS data
     * source to XML.
     *
     * @param document              document dom element.
     * @return                      xml element in String form.
     * @throws KeyChangeException   Throws when:
     *                              <ul>
     *                                  <li>If a configuration error occurred while creating new Transformer. </li>
     *                                  <li>If an error occurred while transforming Document element to XML.</li>
     *                                  <li>If an I/O  exception occurs while closing StreamWriter created to
     *                                  transform Document element to xml.</li>
     *                              </ul>
     */
    private String transformDomToXml(Document document) throws KeyChangeException {
        Transformer transformer;
        try {
            transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, KeyChangeConstants.YES);
        } catch (TransformerConfigurationException e) {
            throw new KeyChangeException("Configuration error occurred while creating new Transformer.", e);
        }

        StringWriter stringWriter = null;
        try {
            stringWriter = new StringWriter();
            StreamResult result = new StreamResult(stringWriter);
            DOMSource source = new DOMSource(document);
            transformer.transform(source, result);
            return stringWriter.toString();
        } catch (TransformerException e) {
            throw new KeyChangeException("Error occurred while transforming Document element to XML.", e);
        } finally {
            if (stringWriter != null) {
                try {
                    stringWriter.close();
                } catch (IOException e) {
                    throw new KeyChangeException("Error closing stream writer.", e);
                }
            }
        }
    }

    /**
     * This method is used to get document element from the resource content. DSS data source content was
     * taken to a document element.
     *
     * @param builder               builder which is used to parse the XML configuration.
     * @param resource              resource which includes the content to be converted.
     * @return                      document element.
     * @throws KeyChangeException   Throws when:
     *                              <ul>
     *                                  <li>SAXException if a Document builder parser error occurs.</li>
     *                                  <li>IOException if an input output error while getting DSS data source.</li>
     *                                  <li>RegistryException while getting resource content.</li>
     *                              </ul>
     */
    private Document getDocumentElement(DocumentBuilder builder, Resource resource) throws KeyChangeException {
        try {
            return builder.parse(new InputSource(new StringReader(RegistryUtils.decodeBytes(
                    (byte[]) resource.getContent()))));
        } catch (SAXException e) {
            throw new KeyChangeException("Document builder parser error.", e);
        } catch (IOException e) {
            throw new KeyChangeException("Input output error while getting DSS data source from " +
                    KeyChangeConstants.DSS_DATA_SOURCE_FILE_LOCATION, e);
        } catch (RegistryException e) {
            throw new KeyChangeException("Registry exception while getting resource content from DSS data source "
                    + "resources in " + KeyChangeConstants.DSS_DATA_SOURCE_FILE_LOCATION, e);
        }
    }
}
