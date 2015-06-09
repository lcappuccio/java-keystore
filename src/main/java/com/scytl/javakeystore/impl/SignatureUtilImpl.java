/**
 * $Id$
 *
 * @author lcappuccio
 * @date 08/04/2015 12:20
 * <p>
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 * <p>
 * All rights reserved.
 */
package com.scytl.javakeystore.impl;

import com.scytl.javakeystore.api.SignatureUtil;
import com.scytl.javakeystore.exception.SignatureUtilException;
import org.systemexception.logger.impl.LoggerImpl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;

public class SignatureUtilImpl implements SignatureUtil {

	private final static org.systemexception.logger.api.Logger logger = LoggerImpl.getFor(SignatureUtilImpl
			.class);
	private final static String algorithm = "SHA256withRSA";
	private final static int signatureSize = 256;
	private Signature signature;
	private final ArrayList<PublicKey> publicKeys;
	private KeyStore keyStore;
	private PrivateKey privateKey;
	private byte[] byteSignature;
	private FileInputStream inputStream;

	/**
	 * Initializes the object with a path to java key store and its password, see shell script to create the jks
	 *
	 * @param keyStorePath   the keystore path
	 * @param keyStorePasswd the keystore password
	 * @throws SignatureUtilException
	 */
	public SignatureUtilImpl(String keyStorePath, byte[] keyStorePasswd) throws SignatureUtilException {
		ArrayList<Certificate> certificates = new ArrayList();
		ArrayList<String> certificateAliases = new ArrayList();
		this.publicKeys = new ArrayList();
		// Initialize keyStore
		openKeyStore(keyStorePath, keyStorePasswd);
		// Load certificates
		try {
			Enumeration enumeration = keyStore.aliases();
			while (enumeration.hasMoreElements()) {
				String alias = (String) enumeration.nextElement();
				certificateAliases.add(alias);
				certificates.add(keyStore.getCertificate(alias));
			}
			// Initialize signature and load certificates/public keys
			signature = Signature.getInstance(algorithm);
			for (Certificate certificate : certificates) {
				publicKeys.add(certificate.getPublicKey());
			}
		} catch (KeyStoreException | NoSuchAlgorithmException ex) {
			// Not testable because exceptions come not injectable/hardcoded variables
			exceptionHandler(ex, ex.getMessage());
		}
	}

	/**
	 * @param keyStorePath   the keystore path
	 * @param keyStorePasswd the keystore password
	 */
	private void openKeyStore(String keyStorePath, byte[] keyStorePasswd) throws SignatureUtilException {
		logger.info("Opening " + keyStorePath);
		try {
			keyStore = KeyStore.getInstance("jks");
			inputStream = new FileInputStream(new File(keyStorePath));
			keyStore.load(inputStream, new String(keyStorePasswd).toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException ex) {
			exceptionHandler(ex, ex.getMessage());
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException ex) {
					logger.error(ex.getMessage(), ex);
				}
			}
		}
	}

	/**
	 * Preselects a private key in the jks
	 *
	 * @param keyAlias  the key alias
	 * @param keyPasswd the key password
	 * @throws SignatureUtilException
	 */
	@Override
	public void useKey(String keyAlias, char[] keyPasswd) throws SignatureUtilException {
		logger.info("Using key " + keyAlias);
		try {
			privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPasswd);
			if (privateKey == null) {
				exceptionHandler(new SignatureUtilException("Trying to sign a null document"), "Trying to sign a null" +
						" document");
			}
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
			throw new SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 * Initializes the signature object that will be used to verify against the external file signature
	 *
	 * @param document the document to be signed
	 * @throws SignatureUtilException
	 */
	@Override
	public void signDocument(String document) throws SignatureUtilException {
		logger.info("Signing document");
		if (document == null) {
			exceptionHandler(new SignatureUtilException("Trying to sign a null document"), "Trying to sign a null " +
					"document");
		}
		try {
			signature.initSign(privateKey);
			signature.update(document.getBytes());
			byteSignature = signature.sign();
		} catch (InvalidKeyException | SignatureException ex) {
			throw new SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 * Verifies the signature in the external file against the one obtained by the document/key pair
	 *
	 * @param document          the document to verify
	 * @param documentSignature the signature of the document
	 * @return a boolean of the verification
	 * @throws SignatureUtilException
	 */
	@Override
	public Boolean verifySign(String document, byte[] documentSignature) throws SignatureUtilException {
		logger.info("Asked to verify document signature");
		if (documentSignature.length != signatureSize) {
			exceptionHandler(new SignatureUtilException("Invalid signature size: " + documentSignature.length),
					"Invalid signature size: " + documentSignature.length);
		}
		try {
			for (PublicKey publicKey : publicKeys) {
				signature.initVerify(publicKey);
				signature.update(document.getBytes());
				if (signature.verify(documentSignature)) {
					return true;
				}
			}
			return false;
		} catch (InvalidKeyException | SignatureException ex) {
			exceptionHandler(ex, ex.getMessage());
		}
		return false;
	}

	/**
	 * @return
	 */
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
