package com.security.scanner.model;


public class OwaspScore {

    public String status;   // PASS / WARN / FAIL / NOT_CHECKED
    public String severity; // optional
    public int count;

    public OwaspScore(String status) {
        this.status = status;
    }

    public OwaspScore(String status, String severity, int count) {
        this.status = status;
        this.severity = severity;
        this.count = count;
    }
}
