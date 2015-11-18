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

package org.wso2.carbon.keychange.utils;

import org.apache.commons.lang.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.keychange.KeyChangeConstants;
import org.wso2.carbon.keychange.KeyChangeException;
import org.wso2.carbon.keychange.data.ConfigData;
import org.wso2.carbon.keychange.data.KeyChangeData;
import org.wso2.carbon.keychange.data.RegistryData;
import org.wso2.carbon.keychange.data.TenantData;
import org.wso2.carbon.utils.CarbonUtils;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class holds the key change utility related methods to load data from key change.xml file and DSS data source
 * file.
 */
public final class KeyChangeDataUtils {

    /**
     * xPath used to extract xml data.
     */
    private static final XPath xPath = XPathFactory.newInstance().newXPath();

    /**
     * This method is used to get configuration data related to key change.
     *
     * @param   document            keyChange.xml document.
     * @return                      object which holds both old and new key store credentials.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>If xPath expression includes an error when getting key change related
     *                                  configuration data from keyChange.xml document.</li>
     *                                  <li>Invalid arguments supplied for document.</li>
     *                              </ul>
     */
    public static KeyChangeData getKeyChangeConfigData(Document document) throws KeyChangeException {
        // Validate for illegal arguments
        validateDocumentArgument(document);
        KeyChangeData keyChangeData = new KeyChangeData();
        //Get old key data.
        ConfigData oldKeyConfig = new ConfigData();
        try {
            oldKeyConfig.setKeyPath(getValueByXpathExpression(KeyChangeConstants.OLD_KEY_PATH, document));
            oldKeyConfig.setKeyPass(getValueByXpathExpression(KeyChangeConstants.OLD_KEY_PASSWORD_XPATH, document));
            oldKeyConfig.setKeyAlias(getValueByXpathExpression(KeyChangeConstants.OLD_KEY_ALIAS_XPATH, document));
        } catch (XPathExpressionException e) {
            throw new KeyChangeException("Error setting Old key store configuration data", e);
        }
        //Get new key data.
        ConfigData newKeyConfig = new ConfigData();
        try {
            newKeyConfig.setKeyPath(getValueByXpathExpression(KeyChangeConstants.NEW_KEY_XPATH, document));
            newKeyConfig.setKeyPass(getValueByXpathExpression(KeyChangeConstants.NEW_KEY_PASSWORD_XPATH, document));
            newKeyConfig.setKeyAlias(getValueByXpathExpression(KeyChangeConstants.NEW_KEY_ALIAS_XPATH, document));
        } catch (XPathExpressionException e) {
            throw new KeyChangeException("Error setting new key store configuration data", e);
        }
        //Add old nd new key config data to keyChangeData.
        Map<String, ConfigData> configDataMap = new HashMap<String, ConfigData>();
        configDataMap.put(KeyChangeConstants.OLD_KEY_MAP_KEY, oldKeyConfig);
        configDataMap.put(KeyChangeConstants.NEW_KEY_MAP_KEY, newKeyConfig);
        keyChangeData.setConfigDataMap(configDataMap);
        return keyChangeData;
    }

    /**
     * This method is used to get tenant data related to key change.
     *
     * @param   document            keyChange.xml document.
     * @return                      object which holds tenant credentials.
     * @throws  KeyChangeException  If xPath expression includes an error when getting tenants list from keyChange.xml
     *                              document.
     */
    public static KeyChangeData getKeyChangeTenantDataByXML(Document document) throws KeyChangeException {
        // Validate for illegal arguments
        validateDocumentArgument(document);
        KeyChangeData keyChangeData = new KeyChangeData();
        try {
            NodeList nodeList = getNodeListByXpathExpression(KeyChangeConstants.TENANT_DOMAIN_XPATH, document);
            List<TenantData> tenantDataList = new ArrayList<TenantData>();
            for (int i = 0; i < nodeList.getLength(); i++) {
                // Create tenant data object while passing the tenant domain to the constructor.
                TenantData tenantData = new TenantData(nodeList.item(i).getFirstChild().getTextContent());
                tenantDataList.add(tenantData);
            }
            //Adding tenant data to keyChangeData object
            keyChangeData.setTenantDataList(tenantDataList);
        } catch (XPathExpressionException e) {
            throw new KeyChangeException("Error getting tenant list from " + KeyChangeConstants.XML_FILE, e);
        }
        return keyChangeData;
    }

    /**
     * This method is used to get key store changed date from keyChange.xml.
     *
     * @param   document            keyChange.xml document.
     * @return                      which holds registry path of tenant key store.
     * @throws  KeyChangeException  If the xPAth evaluations fails when getting key store changed date from
     *                              keyChange.xml document.
     */
    public static String getKeyChangeDate(Document document) throws KeyChangeException {
        // Validate for illegal arguments
        validateDocumentArgument(document);
        try {
            return getValueByXpathExpression(KeyChangeConstants.KEY_CHANGE_DATE_XPATH, document);
        } catch (XPathExpressionException e) {
            throw new KeyChangeException("Error getting key change date from " + KeyChangeConstants.XML_FILE, e);
        }
    }

    /**
     * This method is used to get key store changed method from keyChange.xml. Methods are 'date' and 'keyChangeXML'.
     *
     * @param   document            keyChange.xml document.
     * @return                      object which holds registry path of tenant key store.
     * @throws  KeyChangeException  If xPath expression includes an error when getting method to iterate over tenants
     *                              from keyChange.xml document.
     */
    public static String getKeyChangeMethod(Document document) throws KeyChangeException {
        // Validate for illegal arguments
        validateDocumentArgument(document);
        try {
            return getValueByXpathExpression(KeyChangeConstants.KEY_CHANGE_METHOD_XPATH, document);
        } catch (XPathExpressionException e) {
            throw new KeyChangeException("Error getting key change method from " + KeyChangeConstants.XML_FILE, e);
        }
    }

    /**
     * Method is used to get encrypted registry data.
     *
     * @param   document            keyChange.xml document.
     * @return                      registry data list with includes registry paths and respective encrypted properties.
     * @throws  KeyChangeException  If xPath expression includes an error when getting registry data from keyChange.xml
     *                              document.
     */
    public static List<RegistryData> getRegistryData(Document document) throws KeyChangeException {
        // Validate for illegal arguments
        validateDocumentArgument(document);
        List<RegistryData> registryDataList = new ArrayList<RegistryData>();
        NodeList nodeList;
        try {
            nodeList = getNodeListByXpathExpression(KeyChangeConstants.KEY_CHANGE_RESOURCE_XPATH, document);
        } catch (XPathExpressionException e) {
            throw new KeyChangeException("Error when getting node list evaluating xPath: " + KeyChangeConstants
                    .KEY_CHANGE_RESOURCE_XPATH, e);
        }
        try {
            for (int i = 0; i < nodeList.getLength(); i++) {
                RegistryData registryData = new RegistryData();
                Element node = (Element) nodeList.item(i);
                registryData.setRegistryPath(xPath.evaluate(KeyChangeConstants.KEY_CHANGE_REGISTRY_XPATH, node).trim());
                // Get registry properties to decrypt using old key and encrypt using new key from keyChange.xml.
                NodeList propertyNodeList = node.getElementsByTagName(KeyChangeConstants.KEY_CHANGE_PROPERTY_XPATH);
                ArrayList<String> propertyList = new ArrayList<String>();
                for (int j = 0; j < propertyNodeList.getLength(); j++) {
                    propertyList.add(propertyNodeList.item(j).getFirstChild().getTextContent().trim());
                }
                registryData.setPropertyKeyList(propertyList);
                //Adding registry data to key change data
                registryDataList.add(registryData);
            }
        } catch (XPathExpressionException e) {
            throw new KeyChangeException("Error when getting node list evaluating xPath: " + KeyChangeConstants
                    .KEY_CHANGE_REGISTRY_XPATH, e);
        }
        return registryDataList;
    }

    /**
     * This method is used validate keyChange.xml files with keyChange.xsd files.
     *
     * @return                      validation status. True if the kyeChange.xml is validated with keyChange.xsd.
     * @throws  KeyChangeException  If keyChange.xml or keyChange.xsd file I/O operations were interrupted or
     *                              xml parsing when parsing keyChange.xml.
     */
    public static boolean validateXML() throws KeyChangeException {
        try {
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new File(CarbonUtils.getCarbonConfigDirPath() + File.separator
                    + KeyChangeConstants.XSD_FILE));
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new File(CarbonUtils.getCarbonConfigDirPath() + File.separator
                    + KeyChangeConstants.XML_FILE)));
            return true;
        } catch (SAXException e) {
            throw new KeyChangeException("Error when validating xml file.", e);
        } catch (IOException e) {
            throw new KeyChangeException("File input error when validating xml or xsd file paths may be incorrect.", e);
        }
    }

    /**
     * This method is used to check whether dss is deployed or not.
     *
     * @param   document            keyChange.xml document.
     * @return                      to check whether dss is enabled or not.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>If XPathExpressionException exception occurs when evaluating xml tag
     *                                  which has the configuration whether DSS is deployed or not.</li>
     *                                  <li>If illegal argument supplied document.</li>
     *                              </ul>
     */
    public static boolean isDssDeployed(Document document) throws KeyChangeException {
        // Validate for illegal arguments
        validateDocumentArgument(document);
        try {
            return Boolean.valueOf(getValueByXpathExpression(KeyChangeConstants.IS_DSS_DEPLOYED_XPATH, document));
        } catch (XPathExpressionException e) {
            throw new KeyChangeException("Error getting DSS deployed or not from " + KeyChangeConstants.XML_FILE, e);
        }
    }

    /**
     * This method is used to get admin username.
     *
     * @param   document            keyChange.xml document.
     * @return                      to check whether dss is enabled or not.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>If XPathExpressionException exception occurs when evaluating xml tag
     *                                  which has the configuration of admin username.</li>
     *                                  <li>If illegal argument supplied document.</li>
     *                              </ul>
     */
    public static String getAdminUsername(Document document) throws KeyChangeException {
        // Validate for illegal arguments
        validateDocumentArgument(document);
        try {
            return String.valueOf(getValueByXpathExpression(KeyChangeConstants.ADMIN_USERNAME_XPATH, document));
        } catch (XPathExpressionException e) {
            throw new KeyChangeException("Error getting admin username from " + KeyChangeConstants.XML_FILE, e);
        }
    }

    /**
     * This method is used to get a XML tag value from a given xPath.
     *
     * @param   xPathExpression             xPath expression.
     * @param   document                    document element of keyChange.xml file.
     * @return                              XML tag value.
     * @throws  XPathExpressionException    Throws when:
     *                                      <ul>
     *                                          <li>If xPath expression includes an error.</li>
     *                                          <li>If invalid arguments supplied for xPathExpression.</li>
     *                                      </ul>
     */
    public static String getValueByXpathExpression(String xPathExpression, Document document)
            throws XPathExpressionException {
        // Validate for illegal arguments.
        validateXpathAndDocumentArguments(xPathExpression, document);
        return xPath.compile(xPathExpression).evaluate(document).trim();
    }

    /**
     * This method is used to get a node from a give xPath.
     *
     * @param   xPathExpression             xPath expression.
     * @param   document                    document element of keyChange.xml file.
     * @return                              Nodes extracted using the xPath expression and document element.
     * @throws  XPathExpressionException    Throws when:
     *                                      <ul>
     *                                          <li>If xPath expression includes an error.</li>
     *                                          <li>If invalid arguments supplied for xPathExpression.</li>
     *                                      </ul>
     */
    public static Node getNodeByXpathExpression(String xPathExpression, Document document)
            throws XPathExpressionException {
        // Validate for illegal arguments.
        validateXpathAndDocumentArguments(xPathExpression, document);
        return (Node) xPath.compile(xPathExpression).evaluate(document, XPathConstants.NODE);

    }

    /**
     * This method is used to get a list node from a give xPath.
     *
     * @param   xPathExpression             xPath expression.
     * @param   document                    document element of keyChange.xml file.
     * @return                              List of nodes extracted using the xPath expression and document element.
     * @throws  XPathExpressionException    Throws when:
     *                                      <ul>
     *                                          <li>If xPath expression includes an error.</li>
     *                                          <li>If invalid arguments supplied for xPathExpression.</li>
     *                                      </ul>
     */
    private static NodeList getNodeListByXpathExpression(String xPathExpression, Document document)
            throws XPathExpressionException {
        // Validate for illegal arguments.
        validateXpathAndDocumentArguments(xPathExpression, document);
        return (NodeList) xPath.compile(xPathExpression).evaluate(document, XPathConstants.NODESET);

    }

    /**
     * This method is used to validate argument for document.
     *
     * @param document  document element supplied.
     */
    private static void validateDocumentArgument(Document document){
        if (document == null) {
            throw new IllegalArgumentException("Invalid arguments supplied for document");
        }
    }

    private static void validateXpathAndDocumentArguments(String xPathExpression, Document document){
        // Validate for illegal arguments
        if (StringUtils.isEmpty(xPathExpression) || document == null) {
            throw new IllegalArgumentException("Invalid arguments supplied for xPathExpression: " + xPathExpression
                    + ", document.");
        }
    }

}
