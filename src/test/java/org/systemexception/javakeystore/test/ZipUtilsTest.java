package org.systemexception.javakeystore.test;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.systemexception.javakeystore.main.Main;
import org.systemexception.javakeystore.pojo.ZipUtils;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author leo
 * @date 26/12/15 13:11
 */
class ZipUtilsTest {

    private final static String TEST_FILE = Main.OUTPUT_PATH + ZipUtils.OUTPUT_FILE;
    private ZipUtils sut;

    @BeforeEach
    void setUp() throws IOException {
        File zipOutput = new File(TEST_FILE);
        zipOutput.delete();
        sut = new ZipUtils();
    }

    @AfterEach
    void tearDown() throws IOException {
        File zipOutput = new File(TEST_FILE);
        zipOutput.delete();
        sut.closeZip();
    }

    @Test
    void add_file_to_zip() throws IOException, URISyntaxException {
        sut = new ZipUtils();
        URL keyStoreURL = ClassLoader.getSystemResource(Main.INPUT_FILE);
        File keyStoreFile = new File(keyStoreURL.toURI());
        sut.addFileToZip(keyStoreFile);
        assertTrue(new File(TEST_FILE).exists());
    }

}