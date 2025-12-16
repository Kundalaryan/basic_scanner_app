package com.security.scanner.web;

import com.security.scanner.core.ScanContext;
import com.security.scanner.core.ScannerModule;
import com.security.scanner.model.Finding;

import java.util.ArrayList;
import java.util.List;

public class HeaderScannerModule implements ScannerModule {

    @Override
    public String name() {
        return "Header Scanner";
    }

    @Override
    public List<Finding> scan(ScanContext context) {

        List<Finding> findings = new ArrayList<>();

        // 🔥 CONDITIONAL EXECUTION
        if (!context.httpsEnabled) {
            return findings;
        }

        HeaderScanner scanner = new HeaderScanner();
        var results = scanner.scan("https://" + context.target);

        results.forEach((k, v) ->
                findings.add(new Finding(
                        "Header Issue",
                        context.target,
                        "Low",
                        v
                ))
        );

        return findings;
    }
}
