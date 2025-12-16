package com.security.scanner.web;

public class DirectoryScanResult {

    public String path;
    public int statusCode;

    public DirectoryScanResult(String path, int statusCode) {
        this.path = path;
        this.statusCode = statusCode;
    }
}
