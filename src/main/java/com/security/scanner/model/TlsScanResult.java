package com.security.scanner.model;

import java.util.Date;

public class TlsScanResult {

    public boolean httpsSupported;
    public boolean httpRedirectsToHttps;
    public Date certExpiry;
    public String issuer;
    public String protocol;

}
