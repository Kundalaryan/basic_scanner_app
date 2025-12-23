package com.security.scanner.owasp;

import com.security.scanner.core.ScanContext;
import com.security.scanner.model.Finding;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class A01AccessControlCheck implements OwaspCheckModule {

    @Override
    public String owaspId() {
        return "A01";
    }

    @Override
    public String name() {
        return "Broken Access Control Indicators";
    }

    @Override
    public List<Finding> scan(ScanContext context) {

        List<Finding> findings = new ArrayList<>();

        if (!context.httpsEnabled) return findings;

        String[] paths = {"/admin", "/manage", "/internal"};

        for (String path : paths) {
            try {
                URL url = new URL("https://" + context.target + path);
                HttpURLConnection conn =
                        (HttpURLConnection) url.openConnection();
                conn.setInstanceFollowRedirects(false);
                conn.setConnectTimeout(2000);

                int status = conn.getResponseCode();

                if (status == 200 || status == 302) {
                    findings.add(new Finding(
                            "OWASP A01",
                            context.target + path,
                            "High",
                            "High",
                            "Sensitive endpoint accessible: HTTP " + status
                    ));
                }

            } catch (Exception ignored) {}
        }

        return findings;
    }
}