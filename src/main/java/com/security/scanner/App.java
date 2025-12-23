package com.security.scanner;
import com.security.scanner.core.CliParser;
import com.security.scanner.core.ScanConfig;
import com.security.scanner.core.ScanOrchestrator;
import com.security.scanner.model.Finding;
import com.security.scanner.model.ScanReport;
import com.security.scanner.report.*;

import java.time.Instant;
import java.util.List;

/**
 * Hello world!
 *
 */
public class App {

    public static void main(String[] args) {

        try {
            ScanConfig config = CliParser.parse(args);

            Instant start = Instant.now();

            ScanOrchestrator orchestrator =
                    new ScanOrchestrator(config);

            List<Finding> rawFindings = orchestrator.run();

            FindingAggregator aggregator = new FindingAggregator();
            List<Finding> findings = aggregator.aggregate(rawFindings);

            SuggestionEngine suggestionEngine = new SuggestionEngine();
            var suggestions = suggestionEngine.generate(findings);


            Instant end = Instant.now();

            ReportGenerator generator = new ReportGenerator();
            ScanReport report =
                    generator.generate(config.target, start, end, findings);
            report.suggestions = suggestions;

            OwaspScorecardGenerator scorecardGenerator =
                    new OwaspScorecardGenerator();

            var scorecard = scorecardGenerator.generate(findings);

            report.owaspScorecard = scorecard;

            ReportWriter writer = new ReportWriter();
            writer.writeJson(report, "scan-report.json");

            System.out.println("\n✅ Scan completed successfully");
            System.out.println("📄 Report written to scan-report.json");
            System.out.println("⏱ Duration: " + report.durationSeconds + " seconds");
            System.out.println("🔎 Findings: " + findings.size());

        } catch (Exception e) {
            System.err.println("Scan failed: " + e.getMessage());
        }
    }
}
