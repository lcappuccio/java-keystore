package org.systemexception.javakeystore.pojo;

import org.systemexception.javakeystore.main.Main;

import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ZipUtils {

    private final ZipOutputStream zipOutput;
    private final byte[] buffer;
    public static final String OUTPUT_FILE = "output.zip";

    public ZipUtils() throws IOException {
        this.buffer = new byte[1024];
        FileOutputStream fos = new FileOutputStream(Main.OUTPUT_PATH + OUTPUT_FILE);
        zipOutput = new ZipOutputStream(fos);
    }

    /**
     * @param fileName the file to be added to the zip
     * @throws IOException
     */
    public void addFileToZip(File fileName) throws IOException {
        ZipEntry zipEntry = new ZipEntry(fileName.getName());
        zipOutput.putNextEntry(zipEntry);
        try (FileInputStream in = new FileInputStream(fileName)) {
            int len;
            while ((len = in.read(buffer)) > 0) {
                zipOutput.write(buffer, 0, len);
            }
        }
        zipOutput.closeEntry();
    }

    /**
     * @throws IOException
     */
    public void closeZip() throws IOException {
        // close it
        zipOutput.close();
    }
}
