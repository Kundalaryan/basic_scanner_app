package com.security.scanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;



public class ReportWriter {

    public void writeJson(Object report, String fileName) throws Exception {

        ObjectMapper mapper = new ObjectMapper();

        // ✅ Enable Java 8 time support
        mapper.registerModule(new JavaTimeModule());

        // Optional: ISO-8601 instead of timestamps
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        mapper.writeValue(new File(fileName), report);
    }
}

