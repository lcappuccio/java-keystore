package org.systemexception.javakeystore.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.systemexception.javakeystore.api.SignatureUtil;
import org.systemexception.javakeystore.exception.SignatureUtilException;
import org.systemexception.javakeystore.impl.SignatureUtilImpl;
import org.systemexception.javakeystore.main.Main;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class SignatureUtilTest {

    private static final String SAMPLE_TEXT_DOCUMENT = "some text document";
    private SignatureUtil sut;
    private static String keyStorePath;

    @BeforeAll
    public static void setUp() throws URISyntaxException {
        URL keyStoreURL = ClassLoader.getSystemResource(Main.KEY_STORE);
        File keyStoreFile = new File(keyStoreURL.toURI());
        keyStorePath = keyStoreFile.getAbsolutePath();
    }

    @Test
    void throwExceptionNotExistingFile() {
        assertThrows(FileNotFoundException.class, () -> sut = new SignatureUtilImpl("abc", "somepassword".getBytes()));
    }

    @Test
    void wrongKeyStorePasswordException() {
        assertThrows(IOException.class, () -> sut = new SignatureUtilImpl(keyStorePath, "abc".getBytes()));

    }

    @Test
    void nonExistingKeyAliasDisplaysError() {
        assertThrows(SignatureUtilException.class, () -> {
            sut = new SignatureUtilImpl(keyStorePath, Main.KEY_STORE_PASSWORD.getBytes());
            // Select private key
            String keyAlias = "some_missing_key_alias";
            char[] keyPasswd = "some_nonexisting_pwd".toCharArray();
            sut.useKey(keyAlias, keyPasswd);
        });

    }

    @Test
    void askToSignNullDocumentThrowsException() {
        try {
            buildEffectiveSut();
        } catch (SignatureUtilException e) {
            throw new RuntimeException(e);
        }
        assertThrows(SignatureUtilException.class, () -> {
            // Sign the document with the preselected key
            sut.signDocument(null);
        });
    }

    @Test
    void throwExceptionOnBadSignature() {
        String testDocument = SAMPLE_TEXT_DOCUMENT;
        try {
            buildEffectiveSut();
            sut.signDocument(testDocument);
        } catch (SignatureException | SignatureUtilException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        assertThrows(SignatureUtilException.class, () -> {
            // Tamper the signature
            byte[] testSignature = sut.getDocumentSignature();
            sut.verifySign(testDocument, Arrays.copyOf(testSignature, testSignature.length - 5));
        });
    }

    @Test
    void throwExceptionOnBadKeyPassword() {
        assertThrows(SignatureUtilException.class, () -> {
            sut = new SignatureUtilImpl(keyStorePath, Main.KEY_STORE_PASSWORD.getBytes());
            // Select private key
            String keyAlias = Main.KEY_ALIAS;
            char[] keyPasswd = "rcpx_WRONG".toCharArray();
            sut.useKey(keyAlias, keyPasswd);
        });
    }

    @Test
    void askToVerifyDocument() throws SignatureUtilException, SignatureException, InvalidKeyException {
        buildEffectiveSut();
        // Sign the document with the preselected key
        String testDocument = SAMPLE_TEXT_DOCUMENT;
        sut.signDocument(testDocument);
        assertTrue(sut.verifySign(testDocument, sut.getDocumentSignature()));
    }

    @Test
    void askToVerifyDocumentWithBadSignature() throws SignatureUtilException, SignatureException,
            InvalidKeyException {
        buildEffectiveSut();
        // Sign the document with the preselected key
        String testDocument = SAMPLE_TEXT_DOCUMENT;
        sut.signDocument(testDocument);
        assertFalse(sut.verifySign(testDocument, new byte[256]));
    }

    @Test
    void askToVerifyTamperedDocument() throws SignatureUtilException, SignatureException, InvalidKeyException {
        buildEffectiveSut();
        // Sign the document with the preselected key
        String testDocument = SAMPLE_TEXT_DOCUMENT;
        sut.signDocument(testDocument);
        assertFalse(sut.verifySign(testDocument.substring(0, testDocument.length() - 5), sut.getDocumentSignature()));
    }

    /**
     * Build SignatureUtil for tests
     *
     * @throws SignatureUtilException
     */
    private void buildEffectiveSut() throws SignatureUtilException {
        try {
            sut = new SignatureUtilImpl(keyStorePath, Main.KEY_STORE_PASSWORD.getBytes());
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException e) {
            e.printStackTrace();
        }
        // Select private key
        String keyAlias = Main.KEY_ALIAS;
        char[] keyPasswd = "rcpx".toCharArray();
        sut.useKey(keyAlias, keyPasswd);
    }
}
