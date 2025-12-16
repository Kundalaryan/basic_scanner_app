package com.security.scanner.model;

public class PortScanResult {

    public int port;
    public String service;

    public PortScanResult(int port, String service) {
        this.port = port;
        this.service = service;
    }
}
