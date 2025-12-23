package com.security.scanner.owasp;

import com.security.scanner.core.ScanContext;
import com.security.scanner.model.Finding;

import java.util.List;

public interface OwaspCheckModule {

    String owaspId();   // e.g. A01
    String name();      // Human readable

    List<Finding> scan(ScanContext context);
}