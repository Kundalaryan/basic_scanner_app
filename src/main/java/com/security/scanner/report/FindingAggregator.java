package com.security.scanner.report;

import com.security.scanner.model.Finding;

import java.util.*;
import java.util.stream.Collectors;

public class FindingAggregator {

    public List<Finding> aggregate(List<Finding> findings) {

        Map<String, List<Finding>> grouped =
                findings.stream()
                        .collect(Collectors.groupingBy(
                                Finding::aggregationKey
                        ));

        List<Finding> aggregated = new ArrayList<>();

        for (List<Finding> group : grouped.values()) {

            if (group.size() == 1) {
                aggregated.add(group.get(0));
                continue;
            }

            Finding base = group.get(0);

            String evidenceSummary =
                    "Affected items: " + group.size() +
                            ", Examples: " +
                            group.stream()
                                    .limit(5)
                                    .map(f -> f.evidence)
                                    .toList();

            aggregated.add(new Finding(
                    base.type,
                    base.target,
                    base.severity,
                    base.confidence,
                    evidenceSummary
            ));
        }

        return aggregated;
    }
}
