package com.security.scanner.core;

import com.security.scanner.model.Finding;
import com.security.scanner.network.PortScannerModule;
import com.security.scanner.owasp.OwaspOrchestrator;
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

        // 1️⃣ Run core scanner plugins
        for (ScannerModule module : modules) {
            System.out.println("▶ Running: " + module.name());
            allFindings.addAll(module.scan(context));
        }

        // 2️⃣ Run SAFE OWASP checks (POST-PROCESSING)
        OwaspOrchestrator owasp = new OwaspOrchestrator();
        allFindings.addAll(owasp.run(context));

        // 3️⃣ Return combined findings
        return allFindings;
    }
}
