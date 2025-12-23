package com.security.scanner.owasp;

import com.security.scanner.core.ScanContext;
import com.security.scanner.model.Finding;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class A03SensitiveDataCheck implements OwaspCheckModule {

    @Override
    public String owaspId() {
        return "A03";
    }

    @Override
    public String name() {
        return "Sensitive Data Exposure Indicators";
    }

    @Override
    public List<Finding> scan(ScanContext context) {

        List<Finding> findings = new ArrayList<>();

        String[] files = {
                "/.env",
                "/.git/config",
                "/backup.sql",
                "/config.json"
        };

        String base =
                context.httpsEnabled ? "https://" : "http://";

        for (String f : files) {
            try {
                URL url = new URL(base + context.target + f);
                HttpURLConnection conn =
                        (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(2000);

                if (conn.getResponseCode() == 200) {
                    findings.add(new Finding(
                            "OWASP A03",
                            context.target + f,
                            "Critical",
                            "High",
                            "Sensitive file accessible"
                    ));
                }
            } catch (Exception ignored) {}
        }

        return findings;
    }
}