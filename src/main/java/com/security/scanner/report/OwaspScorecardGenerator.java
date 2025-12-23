package com.security.scanner.report;

import com.security.scanner.model.Finding;
import com.security.scanner.model.OwaspScore;

import java.util.*;

public class OwaspScorecardGenerator {

    // These are the OWASP checks you ACTUALLY implemented
    private static final List<String> OWASP_IDS = List.of(
            "A01", "A02", "A03", "A05"
    );

    public Map<String, OwaspScore> generate(List<Finding> findings) {

        Map<String, List<Finding>> grouped = new HashMap<>();

        // Collect OWASP findings
        for (Finding f : findings) {
            if (f.type.startsWith("OWASP")) {
                String id = f.type.split(" ")[1]; // "OWASP A03" → A03
                grouped.computeIfAbsent(id, k -> new ArrayList<>()).add(f);
            }
        }

        Map<String, OwaspScore> scorecard = new LinkedHashMap<>();

        for (String id : OWASP_IDS) {

            List<Finding> owaspFindings = grouped.get(id);

            // ✅ Implemented & clean
            if (owaspFindings == null) {
                scorecard.put(id, new OwaspScore("PASS"));
                continue;
            }

            // ❌ Implemented & issues found
            String worstSeverity = worstSeverity(owaspFindings);

            String status =
                    ("Critical".equals(worstSeverity) || "High".equals(worstSeverity))
                            ? "FAIL"
                            : "WARN";

            scorecard.put(
                    id,
                    new OwaspScore(status, worstSeverity, owaspFindings.size())
            );
        }

        return scorecard;
    }

    private String worstSeverity(List<Finding> findings) {

        List<String> order = List.of("Critical", "High", "Medium", "Low", "Info");

        return findings.stream()
                .map(f -> f.severity)
                .min(Comparator.comparingInt(order::indexOf))
                .orElse("Low");
    }
}
