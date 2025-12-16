package com.security.scanner.web;

import com.security.scanner.core.FileUtil;
import com.security.scanner.core.ScanContext;
import com.security.scanner.core.ScannerModule;
import com.security.scanner.model.Finding;

import java.util.ArrayList;
import java.util.List;

public class DirectoryScannerModule implements ScannerModule {

    @Override
    public String name() {
        return "Directory Scanner";
    }

    @Override
    public List<Finding> scan(ScanContext context) {

        List<Finding> findings = new ArrayList<>();

        // 🔥 CONDITIONAL EXECUTION
        if (!context.openPorts.contains(80) &&
                !context.openPorts.contains(443)) {
            return findings;
        }

        DirectoryScanner scanner = new DirectoryScanner();
        List<String> words =
                FileUtil.loadWordlist(context.config.wordlistPath);

        String baseUrl = context.openPorts.contains(443)
                ? "https://" + context.target
                : "http://" + context.target;

        List<DirectoryScanResult> results =
                scanner.scan(baseUrl, words);

        for (DirectoryScanResult result : results) {

            // 🧠 CONFIDENCE LOGIC (THIS IS THE KEY PART)
            String confidence;
            if (result.statusCode == 200) {
                confidence = "High";
            } else {
                confidence = "Medium"; // 301, 302, 401, 403
            }

            findings.add(new Finding(
                    "Directory Exposure",
                    context.target,
                    "High",
                    confidence,
                    result.path + " → HTTP " + result.statusCode
            ));
        }

        return findings;
    }
}