package com.security.scanner.model;

public class Finding {

    public String type;
    public String target;
    public String severity;
    public String confidence; // Low / Medium / High
    public String evidence;

    public String aggregationKey() {

        if ("Open Port".equals(type)) {
            return type + "|" + target; // keep ports separate
        }

        return type + "|" + severity + "|" + confidence;
    }


    // ✅ OLD CONSTRUCTOR (KEEP IT!)
    public Finding(String type,
                   String target,
                   String severity,
                   String evidence) {

        this(type, target, severity, "Medium", evidence);
    }

    // ✅ NEW CONSTRUCTOR (PHASE 3)
    public Finding(String type,
                   String target,
                   String severity,
                   String confidence,
                   String evidence) {

        this.type = type;
        this.target = target;
        this.severity = severity;
        this.confidence = confidence;
        this.evidence = evidence;
    }
}

