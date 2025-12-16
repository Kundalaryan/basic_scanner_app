package com.security.scanner.web;

import com.security.scanner.core.ScanContext;
import com.security.scanner.core.ScannerModule;
import com.security.scanner.model.Finding;
import com.security.scanner.model.TlsScanResult;

import java.util.ArrayList;
import java.util.List;

public class TlsScannerModule implements ScannerModule {

    @Override
    public String name() {
        return "TLS Scanner";
    }

    @Override
    public List<Finding> scan(ScanContext context) {

        List<Finding> findings = new ArrayList<>();

        // 🔥 CONDITIONAL EXECUTION
        if (!context.openPorts.contains(443)) {
            return findings;
        }

        TlsScanner scanner = new TlsScanner();
        TlsScanResult tls = scanner.scan(context.target);

        context.httpsEnabled = tls.httpsSupported;

        if (!tls.httpsSupported) {
            findings.add(new Finding(
                    "TLS",
                    context.target,
                    "High",
                    "HTTPS not supported"
            ));
            return findings;
        }

        if (!tls.httpRedirectsToHttps) {
            findings.add(new Finding(
                    "TLS",
                    context.target,
                    "Medium",
                    "HTTP does not redirect to HTTPS"
            ));
        }

        findings.add(new Finding(
                "TLS",
                context.target,
                "Low",
                "TLS Cipher: " + tls.protocol
        ));

        findings.add(new Finding(
                "TLS",
                context.target,
                "Low",
                "Certificate issuer: " + tls.issuer
        ));

        return findings;
    }
}