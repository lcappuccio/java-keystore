package org.systemexception.javakeystore.main;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.systemexception.javakeystore.exception.SignatureUtilException;
import org.systemexception.javakeystore.impl.SignatureUtilImpl;
import org.systemexception.javakeystore.pojo.ZipUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger(Main.class.getName());

    private static final String INPUT_PATH = "input";
    public static final String INPUT_FILE = "lorem_ipsum.txt";
    public static final String OUTPUT_PATH = System.getProperty("user.dir") + File.separator + "target" +
            File.separator;
    public static final String KEY_STORE = "client.jks";
    public static final String KEY_STORE_PASSWORD = "rcpxrcpx";
    public static final String KEY_ALIAS = "client";
    private static final String KEY_PASSWORD = "rcpx";
    private static final String FALSIFIED_TAMPERED_DOCUMENT = "Falsified document";

    public static void main(String[] args) throws IOException, SignatureUtilException, KeyStoreException,
            NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException {

        String keyStorePath = INPUT_PATH + File.separator + KEY_STORE;
        byte[] keyStorePasswd = KEY_STORE_PASSWORD.getBytes();

        // Create keystore
        SignatureUtilImpl keystore = new SignatureUtilImpl(keyStorePath, keyStorePasswd);

        // Select private key
        char[] keyPasswd = KEY_PASSWORD.toCharArray();
        keystore.useKey(KEY_ALIAS, keyPasswd);

        // Read a document
        String loremIpsum = readTextFile(INPUT_PATH + File.separator + INPUT_FILE);
        LOGGER.info("\n*** CLEAR TEXT DOCUMENT ***");
        LOGGER.info(loremIpsum);

        // Sign the document with the preselected key
        keystore.signDocument(loremIpsum);

        // Verify signature
        LOGGER.info("\n*** VERIFY SIGNATURE ***");
        LOGGER.info("Document signature is valid: {}",
                keystore.verifySign(loremIpsum, keystore.getDocumentSignature()));
        assert (keystore.verifySign(loremIpsum, keystore.getDocumentSignature()));
        // Negative case
        LOGGER.info("Falsified document signature is valid: {}",
                keystore.verifySign(FALSIFIED_TAMPERED_DOCUMENT, keystore.getDocumentSignature()));
        assert (!keystore.verifySign(FALSIFIED_TAMPERED_DOCUMENT, keystore.getDocumentSignature()));

        // Save document and signature to ZIP
        ZipUtils zipUtil = new ZipUtils();
        zipUtil.addFileToZip(new File(INPUT_PATH + File.separator + INPUT_FILE));
        File signatureFile = new File(OUTPUT_PATH + "lorem_ipsum.txt.sig");
        writeTextToFile(new String(keystore.getDocumentSignature()), signatureFile);
        zipUtil.addFileToZip(signatureFile);
        zipUtil.closeZip();
    }

    /**
     * @param fileName the source file to read
     * @return the document as string
     * @throws UnsupportedEncodingException
     * @throws IOException
     */
    private static String readTextFile(String fileName) throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(fileName));
        return new String(encoded, StandardCharsets.UTF_8);
    }

    /**
     * @param text     the text document
     * @param fileName the destination filename
     * @throws FileNotFoundException
     * @throws IOException
     */
    private static void writeTextToFile(String text, File fileName) throws IOException {
        FileUtils.writeStringToFile(fileName, text);
    }
}
