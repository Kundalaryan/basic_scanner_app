package com.security.scanner.core;

import com.security.scanner.model.Finding;
import com.security.scanner.network.PortScannerModule;
import com.security.scanner.web.*;

import java.util.ArrayList;
import java.util.List;

public class ScanOrchestrator {

    private final ScanContext context;
    private final List<ScannerModule> modules = new ArrayList<>();

    public ScanOrchestrator(ScanConfig config) {
        this.context = new ScanContext(config);

        // 🔌 Register plugins
        modules.add(new PortScannerModule());
        modules.add(new TlsScannerModule());
        modules.add(new HeaderScannerModule());
        modules.add(new FingerprintScannerModule());
        modules.add(new DirectoryScannerModule());
        modules.add(new WordPressScannerModule());
    }

    public List<Finding> run() {

        List<Finding> allFindings = new ArrayList<>();

        for (ScannerModule module : modules) {
            System.out.println("▶ Running: " + module.name());
            allFindings.addAll(module.scan(context));
        }

        return allFindings;
    }
}
