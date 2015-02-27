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
 * This class holds the config data that is related to key store data retrieved from keyChange.xml.
 */
public class ConfigData {

    /**
     * Key store path.
     */
    private String keyPath;

    /**
     * Key store password.
     */
    private String keyPass;

    /**
     * Key store alias.
     */
    private String keyAlias;

    /**
     * Key store changed timestamp.
     */
    private String keyStoreChangeDate;

    /**
     * This method used to get key store path.
     *
     * @return  directory path to the key store file.
     */
    public String getKeyPath() {
        return keyPath;
    }

    /**
     * This method is used to set key store path.
     *
     * @param   keyPath directory path to the key store file.
     */
    public void setKeyPath(String keyPath) {
        this.keyPath = keyPath;
    }

    /**
     * This method is used to get key store password.
     *
     * @return  key store password.
     */
    public String getKeyPass() {
        return keyPass;
    }

    /**
     * This method is used to set key store password.
     *
     * @param   keyPass key store password.
     */
    public void setKeyPass(String keyPass) {
        this.keyPass = keyPass;
    }

    /**
     * This method is used to get key store alias.
     *
     * @return  key store alias.
     */
    public String getKeyAlias() {
        return keyAlias;
    }

    /**
     * This method is used to set key store alias.
     *
     * @param   keyAlias    key store alias.
     */
    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    /**
     * This method is used to get kwy store changed date.
     *
     * @return  key store change date
     */
    public String getKeyStoreChangeDate() {
        return keyStoreChangeDate;
    }

    /**
     * This method is used to set key store changed date
     * @param   keyStoreChangeDate  key store change date
     */
    public void setKeyStoreChangeDate(String keyStoreChangeDate) {
        this.keyStoreChangeDate = keyStoreChangeDate;
    }
}
