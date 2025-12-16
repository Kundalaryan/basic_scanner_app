package com.security.scanner.report;

import com.security.scanner.model.Finding;

import java.util.*;

public class SuggestionEngine {

    public Map<String, List<String>> generate(List<Finding> findings) {

        Map<String, List<String>> suggestions = new HashMap<>();

        for (Finding finding : findings) {

            suggestions.putIfAbsent(
                    finding.type,
                    defaultSuggestionsFor(finding)
            );
        }

        return suggestions;
    }

    private List<String> defaultSuggestionsFor(Finding finding) {

        return switch (finding.type) {

            case "Directory Exposure" -> List.of(
                    "Verify authentication on exposed directories",
                    "Restrict access using IP allowlists or VPN",
                    "Disable directory listing on the server"
            );

            case "Open Port" -> List.of(
                    "Confirm the service is required",
                    "Restrict access via firewall rules",
                    "Ensure the service is properly hardened"
            );

            case "TLS" -> List.of(
                    "Enforce HTTPS for all endpoints",
                    "Enable HTTP to HTTPS redirection",
                    "Use strong TLS configurations and ciphers"
            );

            case "Header Issue" -> List.of(
                    "Add missing security headers",
                    "Review Content Security Policy",
                    "Harden HTTP response headers"
            );

            case "WordPress" -> List.of(
                    "Restrict access to wp-admin",
                    "Enable strong authentication",
                    "Keep WordPress core and plugins updated"
            );

            default -> List.of(
                    "Manually review this finding",
                    "Assess the business impact before remediation"
            );
        };
    }
}