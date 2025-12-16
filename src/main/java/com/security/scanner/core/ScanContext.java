package com.security.scanner.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ScanContext {

    public final String target;
    public final ScanConfig config;

    // Shared scan knowledge
    public List<Integer> openPorts = new ArrayList<>();
    public boolean httpsEnabled = false;

    // Generic shared storage
    public Map<String, Object> data = new HashMap<>();

    public ScanContext(ScanConfig config) {
        this.config = config;
        this.target = config.target;
    }
}
