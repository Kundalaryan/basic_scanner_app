package com.security.scanner.owasp;

import com.security.scanner.core.ScanContext;
import com.security.scanner.model.Finding;

import java.util.ArrayList;
import java.util.List;

public class OwaspOrchestrator {

    private final List<OwaspCheckModule> checks = new ArrayList<>();

    public OwaspOrchestrator() {
        checks.add(new A01AccessControlCheck());
        checks.add(new A02CryptoCheck());
        checks.add(new A03SensitiveDataCheck());
        checks.add(new A05SecurityMisconfigurationCheck());
    }

    public List<Finding> run(ScanContext context) {

        List<Finding> findings = new ArrayList<>();

        for (OwaspCheckModule check : checks) {
            findings.addAll(check.scan(context));
        }

        return findings;
    }
}
