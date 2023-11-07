// Author: Sean Pesce
//
// References:
//   https://dzone.com/articles/execute-mtls-calls-using-java

package com.seanpesce.http;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;


public class MtlsHttpClient {

    // public static final HostnameVerifier insecureHostnameVerifier = new HostnameVerifier() {
    //     public boolean verify(String hostname, SSLSession sslSession) {
    //         return true;
    //     }
    // };


    // public static final TrustManager[] insecureTrustManager = {
    //     new X509TrustManager() {
    //         public X509Certificate[] getAcceptedIssuers() {
    //             return new X509Certificate[0];
    //         }

    //         public void checkClientTrusted(
    //                 X509Certificate[] certificates, String authType) {
    //         }

    //         public void checkServerTrusted(
    //                 X509Certificate[] certificates, String authType) {
    //         }
    //     }
    // };



    // @TODO: Actually implement mTLS client in Java instead of using this work-around
    public static String mtlsHttpGet(String url, String clientCertPath, String clientPrivkeyPath, String caCertPath, boolean insecure) {
        final String[] curlCmdBase = new String[]{ "curl", "-s", "--cert", clientCertPath, "--key", clientPrivkeyPath, "--cacert", caCertPath };
        String[] curlCmd = null;
        if (insecure) {
            curlCmd = Arrays.copyOf(curlCmdBase, curlCmdBase.length + 2);
            curlCmd[curlCmd.length-2] = "-k";
            curlCmd[curlCmd.length-1] = url;
        } else {
            curlCmd = Arrays.copyOf(curlCmdBase, curlCmdBase.length + 1);
            curlCmd[curlCmd.length-1] = url;
        }

        System.err.println("[INFO] HTTP GET " + url);

        Process subproc = null;
        BufferedReader stdout = null;
        BufferedReader stderr = null;
        String output = "";
        try {
            subproc = Runtime.getRuntime().exec(curlCmd);
            stdout = new BufferedReader(new InputStreamReader(subproc.getInputStream()));
            stderr = new BufferedReader(new InputStreamReader(subproc.getErrorStream()));

            String line = null;
            while ((line = stdout.readLine()) != null) {
                output += line;
            }
            line = null;
            while ((line = stderr.readLine()) != null) {
                output += line;
            }
        } catch (IOException ex) {
            return null;
        }

        return output;
    }

}
