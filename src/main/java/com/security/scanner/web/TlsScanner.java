package com.security.scanner.web;

import com.security.scanner.model.TlsScanResult;

import javax.net.ssl.HttpsURLConnection;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.X509Certificate;

public class TlsScanner {

    public TlsScanResult scan(String host) {

        TlsScanResult result = new TlsScanResult();

        // 1️⃣ HTTPS + certificate check
        try {
            URL httpsUrl = new URL("https://" + host);
            HttpsURLConnection conn =
                    (HttpsURLConnection) httpsUrl.openConnection();

            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.connect();

            result.httpsSupported = true;

            // TLS cipher suite (indirect protocol indicator)
            result.protocol = conn.getCipherSuite();

            // Certificate info
            X509Certificate cert =
                    (X509Certificate) conn.getServerCertificates()[0];

            result.certExpiry = cert.getNotAfter();
            result.issuer = cert.getIssuerDN().getName();

        } catch (Exception e) {
            result.httpsSupported = false;
        }

        // 2️⃣ HTTP → HTTPS redirect check
        try {
            URL httpUrl = new URL("http://" + host);
            HttpURLConnection conn =
                    (HttpURLConnection) httpUrl.openConnection();

            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(3000);
            conn.connect();

            String location = conn.getHeaderField("Location");

            if (location != null && location.startsWith("https://")) {
                result.httpRedirectsToHttps = true;
            }

        } catch (Exception ignored) {}

        return result;
    }
}
