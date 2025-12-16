package com.security.scanner.core;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class FileUtil {

    public static List<String> loadWordlist(String path) {
        try {
            if (Files.exists(Path.of(path))) {
                return Files.readAllLines(Path.of(path));
            }

            try (BufferedReader br =
                         new BufferedReader(new InputStreamReader(
                                 FileUtil.class
                                         .getClassLoader()
                                         .getResourceAsStream(path)))) {
                return br.lines().toList();
            }

        } catch (Exception e) {
            throw new RuntimeException("Failed to load wordlist: " + path);
        }
    }
}
