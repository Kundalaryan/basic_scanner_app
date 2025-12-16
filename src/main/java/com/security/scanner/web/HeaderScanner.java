package com.security.scanner.web;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class HeaderScanner {

    public Map<String, String> scan(String urlStr) {
        Map<String, String> findings = new HashMap<>();

        try {
            URL url = new URL(urlStr);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.setConnectTimeout(3000);

            Map<String, java.util.List<String>> headers = con.getHeaderFields();

            if (!headers.containsKey("Content-Security-Policy")) {
                findings.put("CSP", "Missing Content-Security-Policy");
            }
            if (!headers.containsKey("Strict-Transport-Security")) {
                findings.put("HSTS", "Missing HSTS header");
            }

            String server = con.getHeaderField("Server");
            if (server != null) {
                findings.put("Server", "Server header exposed: " + server);
            }

        } catch (Exception e) {
            findings.put("ERROR", e.getMessage());
        }
        return findings;
    }
}

