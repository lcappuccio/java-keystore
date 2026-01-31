package org.systemexception.javakeystore.api;

import org.systemexception.javakeystore.exception.SignatureUtilException;

import java.security.InvalidKeyException;
import java.security.SignatureException;

public interface SignatureUtil {

    /**
     * @param keyAlias  the key alias
     * @param keyPasswd the key password
     * @throws SignatureUtilException
     */
    void useKey(String keyAlias, char[] keyPasswd) throws SignatureUtilException;

    /**
     * @param document the document to sign
     * @throws SignatureUtilException
     */
    void signDocument(String document) throws SignatureUtilException, InvalidKeyException, SignatureException;

    /**
     * @param document          the document to verify
     * @param documentSignature the signature to verify
     * @return the signature verification status
     * @throws SignatureUtilException
     */
    Boolean verifySign(String document, byte[] documentSignature) throws SignatureUtilException, InvalidKeyException, SignatureException;

    /**
     *
     * @return
     */
    byte[] getDocumentSignature();
}
