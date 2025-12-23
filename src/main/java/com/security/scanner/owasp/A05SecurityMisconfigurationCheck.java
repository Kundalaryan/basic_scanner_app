package com.security.scanner.owasp;

import com.security.scanner.core.ScanContext;
import com.security.scanner.model.Finding;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class A05SecurityMisconfigurationCheck implements OwaspCheckModule {

    @Override
    public String owaspId() {
        return "A05";
    }

    @Override
    public String name() {
        return "Security Misconfiguration";
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<Finding> scan(ScanContext context) {

        List<Finding> findings = new ArrayList<>();

        Map<String, String> headerIssues =
                (Map<String, String>) context.data.get("headers");

        if (headerIssues == null || headerIssues.isEmpty()) {
            return findings;
        }

        // 🚩 Missing critical headers
        if (headerIssues.containsKey("Missing HSTS header")) {
            findings.add(new Finding(
                    "OWASP A05",
                    context.target,
                    "High",
                    "High",
                    "HSTS header missing"
            ));
        }

        if (headerIssues.containsKey("Missing Content-Security-Policy")) {
            findings.add(new Finding(
                    "OWASP A05",
                    context.target,
                    "Medium",
                    "Medium",
                    "Content-Security-Policy not configured"
            ));
        }

        // 🚩 Server banner exposure
        if (headerIssues.containsKey("Server header exposed")) {
            findings.add(new Finding(
                    "OWASP A05",
                    context.target,
                    "Low",
                    "High",
                    "Server banner exposed: " + headerIssues.get("Server header exposed")
            ));
        }

        return findings;
    }
}
