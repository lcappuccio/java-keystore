package org.systemexception.javakeystore.impl;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.systemexception.javakeystore.api.SignatureUtil;
import org.systemexception.javakeystore.exception.SignatureUtilException;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Objects;

public class SignatureUtilImpl implements SignatureUtil {

    private static final Logger logger = LogManager.getLogger(SignatureUtilImpl.class);
    private static final String ALGORITHM = "SHA256withRSA";
    private static final int SIGNATURE_SIZE = 256;
    private final Signature signature;
    private final ArrayList<PublicKey> publicKeys;
    private KeyStore keyStore;
    private PrivateKey privateKey;
    private byte[] byteSignature;

    /**
     * Initializes the object with a path to java key store and its password, see shell script to create the jks
     *
     * @param keyStorePath
     * @param keyStorePasswd
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     */
    public SignatureUtilImpl(String keyStorePath, byte[] keyStorePasswd) throws NoSuchAlgorithmException,
            KeyStoreException, IOException, CertificateException {
        logger.debug("Initializing SignatureUtil with algorithm: {}", ALGORITHM);
        ArrayList<Certificate> certificates = new ArrayList<>();
        this.publicKeys = new ArrayList<>();
        // Initialize keyStore
        openKeyStore(keyStorePath, keyStorePasswd);
        // Load certificates
        logger.debug("Loading certificates from keystore");
        Enumeration<String> enumeration = keyStore.aliases();
        while (enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            logger.debug("Found certificate alias: {}", alias);
            certificates.add(keyStore.getCertificate(alias));
        }
        // Initialize signature and load certificates/public keys
        signature = Signature.getInstance(ALGORITHM);
        for (Certificate certificate : certificates) {
            publicKeys.add(certificate.getPublicKey());
        }
        logger.info("SignatureUtil initialized successfully with {} certificate(s)", certificates.size());
    }

    /**
     * @param keyStorePath   the keystore path
     * @param keyStorePasswd the keystore password
     */
    private void openKeyStore(String keyStorePath, byte[] keyStorePasswd) throws IOException,
            KeyStoreException, CertificateException, NoSuchAlgorithmException {
        logger.info("Opening keystore: {}", keyStorePath);
        logger.debug("Keystore type: jks");
        keyStore = KeyStore.getInstance("jks");
        try (FileInputStream inputStream = new FileInputStream(keyStorePath)) {
            keyStore.load(inputStream, new String(keyStorePasswd).toCharArray());
            logger.debug("Keystore loaded successfully");
        } catch (IOException e) {
            logger.error("Failed to open keystore at path: {}", keyStorePath, e);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void useKey(String keyAlias, char[] keyPasswd) throws SignatureUtilException {
        logger.info("Using key with alias: {}", keyAlias);
        try {
            privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPasswd);
            if (privateKey == null) {
                String errorMessage = "Key not found for alias: " + keyAlias;
                exceptionHandler(new SignatureUtilException(errorMessage), errorMessage);
            }
            logger.debug("Private key retrieved successfully for alias: {}", keyAlias);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            String errorMessage = "Failed to retrieve key for alias: " + keyAlias;
            exceptionHandler(ex, errorMessage);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void signDocument(String document) throws SignatureUtilException, InvalidKeyException, SignatureException {
        logger.info("Signing document");
        if (document == null) {
            String errorMessage = "Cannot sign null document";
            exceptionHandler(new SignatureUtilException(errorMessage), errorMessage);
        }
        logger.debug("Document size: {} bytes", document.length());
        signature.initSign(privateKey);
        signature.update(Objects.requireNonNull(document).getBytes());
        byteSignature = signature.sign();
        logger.info("Document signed successfully, signature size: {} bytes", byteSignature.length);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean verifySign(String document, byte[] documentSignature) throws SignatureUtilException,
            InvalidKeyException, SignatureException {
        logger.info("Verifying document signature");
        logger.debug("Signature size: {} bytes, expected: {} bytes", documentSignature.length, SIGNATURE_SIZE);
        if (documentSignature.length != SIGNATURE_SIZE) {
            String errorMessage = "Invalid signature size: " + documentSignature.length +
                    " (expected: " + SIGNATURE_SIZE + ")";
            exceptionHandler(new SignatureUtilException(errorMessage), errorMessage);
        }
        logger.debug("Checking signature against {} public key(s)", publicKeys.size());
        for (PublicKey publicKey : publicKeys) {
            signature.initVerify(publicKey);
            signature.update(document.getBytes());
            if (signature.verify(documentSignature)) {
                logger.info("Signature verification successful");
                return true;
            }
        }
        logger.warn("Signature verification failed - no matching public key found");
        return false;
    }

    /**
     * @return the document signature
     */
    @Override
    public byte[] getDocumentSignature() {
        return byteSignature;
    }

    /**
     * Handle exception
     *
     * @param exception the exception
     * @param message   the message of the exception
     */
    private void exceptionHandler(Exception exception, String message) throws SignatureUtilException {
        logger.error(message, exception);
        throw new SignatureUtilException(exception.getMessage());
    }
}
