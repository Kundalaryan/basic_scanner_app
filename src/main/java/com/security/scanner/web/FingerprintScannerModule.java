package com.security.scanner.web;

import com.security.scanner.core.ScanContext;
import com.security.scanner.core.ScannerModule;
import com.security.scanner.model.Finding;
import com.security.scanner.model.TechnologyFingerprint;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class FingerprintScannerModule implements ScannerModule {

    @Override
    public String name() {
        return "Technology Fingerprinting";
    }

    @Override
    public List<Finding> scan(ScanContext context) {

        List<Finding> findings = new ArrayList<>();
        TechnologyFingerprint fp = new TechnologyFingerprint();

        try {
            URL url = new URL("https://" + context.target);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.connect();

            String server = conn.getHeaderField("Server");
            String poweredBy = conn.getHeaderField("X-Powered-By");

            if (server != null) {
                fp.servers.add(server);
            }
            if (poweredBy != null) {
                fp.frameworks.add(poweredBy);
            }

            // Basic CMS heuristics
            if (conn.getHeaderField("X-WP-Total") != null) {
                fp.cms.add("WordPress");
            }

        } catch (Exception ignored) {}

        // Save fingerprint into context
        context.data.put("fingerprint", fp);

        if (!fp.servers.isEmpty()) {
            findings.add(new Finding(
                    "Fingerprint",
                    context.target,
                    "Low",
                    "Server detected: " + fp.servers
            ));
        }

        if (!fp.frameworks.isEmpty()) {
            findings.add(new Finding(
                    "Fingerprint",
                    context.target,
                    "Low",
                    "Framework detected: " + fp.frameworks
            ));
        }

        if (!fp.cms.isEmpty()) {
            findings.add(new Finding(
                    "Fingerprint",
                    context.target,
                    "Low",
                    "CMS detected: " + fp.cms
            ));
        }

        return findings;
    }
}