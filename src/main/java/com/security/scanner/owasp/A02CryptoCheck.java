package com.security.scanner.owasp;

import com.security.scanner.core.ScanContext;
import com.security.scanner.model.Finding;

import java.util.ArrayList;
import java.util.List;

public class A02CryptoCheck implements OwaspCheckModule {

    @Override
    public String owaspId() {
        return "A02";
    }

    @Override
    public String name() {
        return "Cryptographic Failures";
    }

    @Override
    public List<Finding> scan(ScanContext context) {

        List<Finding> findings = new ArrayList<>();

        if (!context.httpsEnabled) {
            findings.add(new Finding(
                    "OWASP A02",
                    context.target,
                    "High",
                    "High",
                    "HTTPS is not enforced"
            ));
        }

        return findings;
    }
}