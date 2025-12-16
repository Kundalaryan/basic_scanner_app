package com.security.scanner.core;

import com.security.scanner.model.Finding;

import java.util.List;

public interface ScannerModule {

    String name();

    List<Finding> scan(ScanContext context);
}