package com.security.scanner.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public class ScanReport {

    public String target;
    public Instant scanStarted;
    public Instant scanFinished;
    public long durationSeconds;

    public Map<String, Long> summary;
    public List<Finding> findings;
    public Map<String, List<String>> suggestions;
    public Map<String, OwaspScore> owaspScorecard;

}