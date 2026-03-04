package org.systemexception.javakeystore.exception;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureUtilException extends Exception {

    private static final Logger logger = LogManager.getLogger(SignatureUtilException.class);

    /**
     * Constructs an instance of <code>SignatureUtilException</code> with the specified detail message.
     *
     * @param msg the detail message.
     */
    public SignatureUtilException(String msg) {
        super(msg);
        logger.error("SignatureUtilException: {}", msg);
    }
}
