// Author: Sean Pesce

package com.seanpesce;


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.validation.constraints.NotNull;


public class Util {

    // Checks if the provided string resolves to a readable file. If so, the file is read and the
    // file data is returned. If not, the provided string is returned unmodified.
    public static String getTextFileDataFromOptionalPath(@NotNull String pathOrData) throws IOException {
        if (!new File(pathOrData).exists()) {
            return pathOrData;
        }
        return new String(Files.readAllBytes(Paths.get(pathOrData)), StandardCharsets.UTF_8);
    }


    // Causes the current thread to sleep for the specified number of milliseconds (or until interrupted)
    public static void sleep(long milliseconds) {
        try {
            Thread.sleep(milliseconds);
        } catch (InterruptedException ex) {
            System.err.println("[WARNING] Sleep operation was interrupted: " + ex.getMessage());
        }
    }


    // Causes the current thread to sleep forever, or until interrupted (e.g., when the user presses Ctrl+C)
    public static void sleepForever() {
        final int delaySecs = 2;
        while (true) {
            sleep(delaySecs * 1000);
        }
    }


    // "Unhexlify"
    public static byte[] hexToBytes(@NotNull String hexStr) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        for (int i = 0; i < hexStr.length(); ) {
            if (Character.isWhitespace(hexStr.charAt(i))) {
                i++;
                continue;
            }
            String octetStr = hexStr.substring(i, i + 2);
            byte b = (byte)Short.parseShort(octetStr, 16);
            output.write(b);
            i += octetStr.length();
        }
        
        return output.toByteArray();
    }


    // "Hexlify"
    public static String bytesToHex(@NotNull byte[] data) {
        final char[] hexAlphabet = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int val = data[i] & 0xFF;
            hexChars[i * 2] = hexAlphabet[val >>> 4];
            hexChars[i * 2 + 1] = hexAlphabet[val & 0x0F];
        }
        return new String(hexChars);
    }
    
}
