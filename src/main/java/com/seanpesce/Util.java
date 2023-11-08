// Author: Sean Pesce

package com.seanpesce;


import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;


public class Util {

    // Checks if the provided string resolves to a readable file. If so, the file is read and the
    // file data is returned. If not, the provided string is returned unmodified.
    public static String getTextFileDataFromOptionalPath(String pathOrData) throws IOException {
        if (!new File(pathOrData).exists()) {
            return pathOrData;
        }
        return new String(Files.readAllBytes(Paths.get(pathOrData)), StandardCharsets.UTF_8);
    }


    // Causes the current thread to sleep forever, or until interrupted (e.g., when the user presses Ctrl+C)
    public static void sleepForever() {
        final int delaySecs = 10;
        while (true) {
            //System.err.println("Sleeping " + delaySecs + " seconds...");
            try {
                Thread.sleep(delaySecs * 1000);
            } catch (InterruptedException ex) {
                System.err.println("[WARNING] Sleep operation was interrupted: " + ex.getMessage());
            }
        }
    }
    
}
