package com.security.scanner.report;

import com.security.scanner.model.Finding;
import com.security.scanner.model.ScanReport;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

public class ReportGenerator {

    public ScanReport generate(
            String target,
            Instant start,
            Instant end,
            List<Finding> findings) {

        ScanReport report = new ScanReport();

        report.target = target;
        report.scanStarted = start;
        report.scanFinished = end;
        report.durationSeconds = Duration.between(start, end).getSeconds();
        report.findings = findings;

        report.summary = findings.stream()
                .collect(Collectors.groupingBy(
                        f -> f.severity.toUpperCase(),
                        Collectors.counting()
                ));

        return report;
    }
}
