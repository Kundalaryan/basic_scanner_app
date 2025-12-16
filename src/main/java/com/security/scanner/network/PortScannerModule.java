package com.security.scanner.network;

import com.security.scanner.core.ScanContext;
import com.security.scanner.core.ScannerModule;
import com.security.scanner.model.Finding;
import com.security.scanner.model.PortScanResult;

import java.util.ArrayList;
import java.util.List;

public class PortScannerModule implements ScannerModule {

    @Override
    public String name() {
        return "Port Scanner";
    }

    @Override
    public List<Finding> scan(ScanContext context) {

        List<Finding> findings = new ArrayList<>();
        PortScanner scanner = new PortScanner();

        List<PortScanResult> results =
                scanner.scan(context.target, context.config.ports);

        for (PortScanResult result : results) {

            context.openPorts.add(result.port); // 🔥 SHARE DATA

            findings.add(new Finding(
                    "Open Port",
                    context.target + ":" + result.port,
                    "Medium",
                    "Service detected: " + result.service
            ));
        }

        return findings;
    }
}