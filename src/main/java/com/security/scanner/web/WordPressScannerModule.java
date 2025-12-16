package com.security.scanner.web;

import com.security.scanner.core.ScanContext;
import com.security.scanner.core.ScannerModule;
import com.security.scanner.model.Finding;
import com.security.scanner.model.TechnologyFingerprint;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class WordPressScannerModule implements ScannerModule {

    @Override
    public String name() {
        return "WordPress Scanner";
    }

    @Override
    public List<Finding> scan(ScanContext context) {

        List<Finding> findings = new ArrayList<>();

        TechnologyFingerprint fp =
                (TechnologyFingerprint) context.data.get("fingerprint");

        if (fp == null || !fp.cms.contains("WordPress")) {
            return findings; // 🔥 CONDITIONAL
        }

        try {
            URL url = new URL("https://" + context.target + "/wp-admin/");
            HttpURLConnection conn =
                    (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.connect();

            if (conn.getResponseCode() == 200 ||
                    conn.getResponseCode() == 302) {

                findings.add(new Finding(
                        "WordPress",
                        context.target + "/wp-admin",
                        "High",
                        "WordPress admin panel exposed"
                ));
            }

        } catch (Exception ignored) {}

        return findings;
    }
}