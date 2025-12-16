package com.security.scanner.core;

import java.util.List;

public class ScanConfig {

    public String target;
    public List<Integer> ports;
    public String wordlistPath;
    public int timeout;

    public ScanConfig(String target,
                      List<Integer> ports,
                      String wordlistPath,
                      int timeout) {
        this.target = target;
        this.ports = ports;
        this.wordlistPath = wordlistPath;
        this.timeout = timeout;
    }
}
