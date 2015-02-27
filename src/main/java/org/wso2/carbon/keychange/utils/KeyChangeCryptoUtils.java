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

import org.apache.axiom.om.util.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.wso2.carbon.keychange.KeyChangeConstants;
import org.wso2.carbon.keychange.KeyChangeException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * This class holds the key change cryptography utility methods.
 * This methods are in implemented in https://svn.wso2.org/repos/wso2/carbon/kernel/branches/4.2.0/core/org.wso2
 * .carbon.core/4.2.0/src/main/java/org/wso2/carbon/core/util/CryptoUtil.java, but the re-implementation is done
 * because in this scenario two key stores for decryption and encryption and in above referenced CryptoUtil.java it
 * uses a single key store.
 */
public final class KeyChangeCryptoUtils {

    /**
     * Variable used to log entries.
     */
    private static final Log log = LogFactory.getLog(KeyChangeCryptoUtils.class);

    /**
     * To get BR reference from keyStore.
     */
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Method used to encrypt a plain text. This.
     *
     * @param   plainTextBytes      text to be encrypted in bytes.
     * @param   keyPath             path to key store. This is configured in keyChange.xml. Cannot be null since
     *                              keyChange.xml is validated through keyChange.xsd.
     * @param   keyPass             key store password. This is configured in keyChange.xml. Cannot be null since
     *                              keyChange.xml is validated through keyChange.xsd.
     * @param   keyAlias            key store alias. This is configured in keyChange.xml. Cannot be null since
     *                              keyChange.xml is validated through keyChange.xsd.
     * @return                      cipher text byte array.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>Encryption fails in getKeyStore, loadKeyStore, getCertificates,
     *                                  getPublicKey, initCipherForEncryption, cipherDoFinal methods.</li>
     *                                  <li>There are no certificates in key store.</li>
     *                              </ul>
     */
    private static byte[] encrypt(byte[] plainTextBytes, String keyPath, String keyPass, String keyAlias) throws
            KeyChangeException {
        // Get key store.
        KeyStore keyStore = getKeyStore();
        // Load key store.
        loadKeyStore(keyStore, keyPath, keyPass);
        // Get Cipher instance.
        Cipher cipher = getCypherInstance();
        // Get public key.
        PublicKey publicKey = getPublicKey(keyStore, keyAlias);
        // Initialize cipher instance for encryption mode.
        initCipherForEncryption(cipher, publicKey);
        // Encrypt data.
        return cipherDoFinal(cipher, plainTextBytes);
    }

    /**
     * Method used to decrypt cipher text.
     *
     * @param   cipherText          cipher text (Encrypted text) to be decrypt.
     * @return                      plain text.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>Encryption fails in getKeyStore, loadKeyStore, getCertificates,
     *                                  getPrivateKey, initCipherForEncryption, cipherDoFinal methods.</li>
     *                                  <li>There are no certificates in key store.</li>
     *                              </ul>
     */
    private static byte[] decrypt(byte[] cipherText, String keyPath, String keyPass, String keyAlias)
            throws KeyChangeException {
        // Get key store.
        KeyStore keyStore = getKeyStore();
        // Load key store.
        loadKeyStore(keyStore, keyPath, keyPass);
        // Get Cipher instance.
        Cipher cipher = getCypherInstance();
        // Get private key.
        PrivateKey privateKey = getPrivateKey(keyStore, keyPass, keyAlias);
        // Initialize cipher instance for decryption mode.
        initCipherForDecryption(cipher, privateKey);
        // Decrypt data.
        return cipherDoFinal(cipher, cipherText);
    }

    /**
     * This method is used to get KeyStore instance for type JKS.
     *
     * @return                      key store instance for type JKS.
     * @throws  KeyChangeException  Throws when no provider supports a KeyStore Service provider interface
     *                              implementation for JKS.
     */
    private static KeyStore getKeyStore() throws KeyChangeException {
        try {
            return KeyStore.getInstance(KeyChangeConstants.KEY_STORE_TYPE);
        } catch (KeyStoreException e) {
            throw new KeyChangeException("No provider supports a KeyStore Service provider interface implementation "
                    + "for JKS in key store", e);
        }
    }

    /**
     * This method is used to load a key store.
     *
     * @param   keyStore            key store used.
     * @param   keyPath             path to key store. This is configured in keyChange.xml. Cannot be null since
     *                              keyChange.xml is validated through keyChange.xsd.
     * @param   keyPass             key store password. This is configured in keyChange.xml. Cannot be null since
     *                              keyChange.xml is validated through keyChange.xsd.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>Key store files fails to open.
     *                                  <li>Certificate issue in key store.</li>
     *                                  <li>Cryptographic algorithm is requested but is not available in the
     *                                  environment.</li>
     *                                  <li>Interrupted I/O operations when reading key store.</li>
     *                              </ul>
     */
    private static void loadKeyStore(KeyStore keyStore, String keyPath, String keyPass) throws KeyChangeException {
        String file = new File(keyPath).getAbsolutePath();
        FileInputStream fileInputStream = null;
        try {
            fileInputStream = new FileInputStream(file);
            // fileInputStream cannot be null since keyPath is not null and file is not null.
            keyStore.load(fileInputStream, keyPass.toCharArray());
        } catch (FileNotFoundException e) {
            throw new KeyChangeException("Attempt to open the file failed in:" + keyPath, e);
        } catch (CertificateException e) {
            throw new KeyChangeException("Certificate issue in: " + keyPath, e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyChangeException("Cryptographic algorithm is requested but is not available in the "
                    + "environment.", e);
        } catch (IOException e) {
            throw new KeyChangeException("Interrupted I/O operations when reading key store.", e);
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    log.error("Error while closing file input stream for key store in: " + keyPath, e);
                }
            }
        }
    }

    /**
     * This method is used to get public key.
     *
     * @param   keyStore            key store used.
     * @param   keyAlias            key store alias. This is configured in keyChange.xml. Cannot be null since
     *                              keyChange.xml is validated through keyChange.xsd.
     * @return                      public key for the key store.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>No provider supports a KeyStore Service provider interface
     *                                  implementation for JKS in key store.</li>
     *                                  <li>There are no certificates in key store.</li>
     *                              </ul>
     */
    private static PublicKey getPublicKey(KeyStore keyStore, String keyAlias) throws KeyChangeException {
        Certificate[] certificateArray;
        try {
            certificateArray = keyStore.getCertificateChain(keyAlias);
        } catch (KeyStoreException e) {
            throw new KeyChangeException("No provider supports a KeyStore Service provider interface implementation "
                    + "for JKS in key store.", e);
        }
        if (certificateArray != null && certificateArray.length > 0) {
            return certificateArray[0].getPublicKey();
        } else {
            throw new KeyChangeException("There are no certificates in key store.");
        }
    }

    /**
     * This method is used to get private key.
     * @param   keyStore            key store used.
     * @param   keyPass             key store password. This is configured in keyChange.xml. Cannot be null since
     *                              keyChange.xml is validated through keyChange.xsd.
     * @param   keyAlias            key store alias. This is configured in keyChange.xml. Cannot be null since
     *                              keyChange.xml is validated through keyChange.xsd.
     * @return                      private key for the key store.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>No provider supports a KeyStore Service provider interface implementation
     *                                  for JKS in key store.</li>
     *                                  <li>Cryptographic algorithm is requested but is not available in the
     *                                  environment.</li>
     *                                  <li>Key store cannot be recovered.</li>
     *                              </ul>
     */
    private static PrivateKey getPrivateKey(KeyStore keyStore, String keyPass, String keyAlias)
            throws KeyChangeException {
        try {
            return (PrivateKey) keyStore.getKey(keyAlias, keyPass.toCharArray());
        } catch (KeyStoreException e) {
            throw new KeyChangeException("No provider supports a KeyStore Service provider interface implementation "
                    + "for JKS in key store.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyChangeException("Cryptographic algorithm is requested but is not available in the "
                    + "environment.", e);
        } catch (UnrecoverableKeyException e) {
            throw new KeyChangeException("Key store cannot be recovered.", e);
        }
    }

    /**
     * This method is used to get Cypher instance for RSA transformation and BC provider.
     *
     * @return                      cypher instance for RSA transformation and BC provider.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>Cryptographic algorithm is requested but is not available in the
     *                                  environment.</li>
     *                                  <li>Security provider for BC is not in the environment.</li>
     *                                  <li>Padding mechanism is not available in environment.</li>
     *                              </ul>
     */
    private static Cipher getCypherInstance() throws KeyChangeException {
        try {
            return Cipher.getInstance(KeyChangeConstants.CIPHER_TRANSFORMATION_METHOD,
                    KeyChangeConstants.CIPHER_PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyChangeException("Cryptographic algorithm is requested but is not available in the "
                    + "environment.", e);
        } catch (NoSuchProviderException e) {
            throw new KeyChangeException("Security provider for BC is not in the environment.", e);
        } catch (NoSuchPaddingException e) {
            throw new KeyChangeException("Padding mechanism is not available in environment.", e);
        }
    }

    /**
     * This method used to init cypher for encryption.
     *
     * @param   cipher              cipher object usd for initialization.
     * @param   publicKey           public key which uses to init cypher.
     * @throws  KeyChangeException  Throws when invalid Keys (invalid encoding, wrong length, uninitialized) in
     *                              certificate.
     */
    private static void initCipherForEncryption(Cipher cipher, PublicKey publicKey) throws
            KeyChangeException {
        try {
            cipher.init(KeyChangeConstants.OPERATION_MODE_ENCRYPTION, publicKey);
        } catch (InvalidKeyException e) {
            throw new KeyChangeException("Invalid Keys (invalid encoding, wrong length, uninitialized) in certificate.",
                    e);
        }
    }

    /**
     * This method used to init cypher for decryption.
     *
     * @param   cipher              cipher object usd for initialization.
     * @param   privateKey          private key which uses to init cypher.
     * @throws  KeyChangeException  Throws when invalid Keys (invalid encoding, wrong length, uninitialized) in
     *                              certificate.
     */
    private static void initCipherForDecryption(Cipher cipher, PrivateKey privateKey) throws
            KeyChangeException {
        try {
            cipher.init(KeyChangeConstants.OPERATION_MODE_DECRYPTION, privateKey);
        } catch (InvalidKeyException e) {
            throw new KeyChangeException("Invalid Keys (invalid encoding, wrong length, uninitialized) in certificate.",
                    e);
        }
    }

    /**
     * This method is used to encrypt or decrypt data with an initialized cipher.
     * <ul>
     *     <li>Encrypts for a cipher initialization with a public key.</li>
     *     <li>Decrypts for a cipher initialization with a private key.</li>
     * </ul>
     *
     * @param   cipher              initializes cipher object using private key or public key.
     * @param   byteStream          byte steam to be encrypt or decrypt.
     * @return                      byte array stream encrypted or decrypted.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>Length of data(byte[]) provided to the cipher is incorrect.</li>
     *                                  <li>Input data(byte[]) not padded properly.</li>
     *                              </ul>
     */
    private static byte[] cipherDoFinal(Cipher cipher, byte[] byteStream) throws KeyChangeException {
        try {
            return cipher.doFinal(byteStream);
        } catch (IllegalBlockSizeException e) {
            throw new KeyChangeException("Length of data(byte[]) provided to the cipher is incorrect.", e);
        } catch (BadPaddingException e) {
            throw new KeyChangeException("Input data(byte[]) not padded properly.", e);
        }
    }

    /**
     * Method used to encrypt and encode the encrypted data to base64.
     *
     * @param   plainTextBytes      text to be encrypted in bytes.
     * @return                      cipher text encrypted and encoded.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>If KeyChangeException occurs while decrypting the cypher text.</li>
     *                                  <li>If invalid arguments supplied for plainTextBytes or keyPath or keyPass or
     *                                  keyAlias</li>
     *                              </ul>
     */
    public static String encryptAndBase64Encode(byte[] plainTextBytes, String keyPath, String keyPass, String keyAlias)
            throws KeyChangeException {
        if (plainTextBytes == null || StringUtils.isEmpty(keyPath) || StringUtils.isEmpty(keyPass) ||
                StringUtils.isEmpty(keyAlias)) {
            throw new IllegalArgumentException("Invalid arguments supplied as follows. plainTextBytes,  keyPath: "
                    + keyPath + ", keyAlias:" + keyAlias + " and keyPass.");
        }
        return Base64.encode(encrypt(plainTextBytes, keyPath, keyPass, keyAlias));
    }

    /**
     * Method used to decode and decrypt cipher text.
     *
     * @param   base64CipherText    text to be encrypted in bytes.
     * @return                      plain text.
     * @throws  KeyChangeException  Throws when:
     *                              <ul>
     *                                  <li>If KeyChangeException occurs while decrypting the cypher text.</li>
     *                                  <li>If invalid arguments supplied for base64CipherText or keyPath or keyPass or
     *                                  keyAlias</li>
     *                              </ul>
     */
    public static byte[] base64DecodeAndDecrypt(String base64CipherText, String keyPath, String keyPass,
            String keyAlias) throws KeyChangeException {
        if (StringUtils.isEmpty(base64CipherText) || StringUtils.isEmpty(keyPath) || StringUtils.isEmpty(keyPass) ||
                StringUtils.isEmpty(keyAlias)) {
            throw new IllegalArgumentException("Invalid arguments supplied as follows. base64CipherText: " +
                    base64CipherText + ",  keyPath: " + keyPath + ", keyAlias:" + keyAlias + " and keyPass.");
        }
        return decrypt(Base64.decode(base64CipherText), keyPath, keyPass, keyAlias);
    }
}
