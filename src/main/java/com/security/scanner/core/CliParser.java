package com.security.scanner.core;

import java.util.ArrayList;
import java.util.List;

public class CliParser {

    public static ScanConfig parse(String[] args) {

        String target = null;
        List<Integer> ports = new ArrayList<>();
        String wordlist = "dirs.txt";
        int timeout = 2000;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--target" -> target = args[++i];
                case "--ports" -> {
                    for (String p : args[++i].split(",")) {
                        ports.add(Integer.parseInt(p));
                    }
                }
                case "--wordlist" -> wordlist = args[++i];
                case "--timeout" -> timeout = Integer.parseInt(args[++i]);
            }
        }

        if (target == null) {
            throw new IllegalArgumentException(
                    "Missing --target\nUsage: --target example.com"
            );
        }

        if (ports.isEmpty()) {
            ports = List.of(21, 22, 80, 443, 3306, 8080);
        }

        return new ScanConfig(target, ports, wordlist, timeout);
    }
}
