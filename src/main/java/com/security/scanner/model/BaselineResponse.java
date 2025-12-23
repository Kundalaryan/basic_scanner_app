package com.security.scanner.model;

public class BaselineResponse {

    public int status;
    public int contentLength;

    public BaselineResponse(int status, int contentLength) {
        this.status = status;
        this.contentLength = contentLength;
    }
}