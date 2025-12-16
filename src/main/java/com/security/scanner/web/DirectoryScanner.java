package com.security.scanner.web;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class DirectoryScanner {

    public List<DirectoryScanResult> scan(String baseUrl, List<String> words) {

        List<DirectoryScanResult> results = new ArrayList<>();

        for (String word : words) {
            try {
                URL url = new URL(baseUrl + "/" + word);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(2000);
                conn.setRequestMethod("GET");

                int status = conn.getResponseCode();

                if (status == 200 || status == 301 ||
                        status == 302 || status == 401 || status == 403) {

                    results.add(new DirectoryScanResult(word, status));
                }

            } catch (Exception ignored) {}
        }
        return results;
    }
}
