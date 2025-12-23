package com.security.scanner.web;

import com.security.scanner.model.BaselineResponse;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class DirectoryScanner {

    public List<DirectoryScanResult> scan(String baseUrl, List<String> words) {

        List<DirectoryScanResult> results = new ArrayList<>();

        BaselineResponse baseline = getBaseline(baseUrl);

        for (String word : words) {

            // 🔕 Ignore dotfiles by default
            if (word.startsWith(".")) continue;

            try {
                URL url = new URL(baseUrl + "/" + word);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(2000);
                conn.setInstanceFollowRedirects(false);

                int status = conn.getResponseCode();
                int length = conn.getContentLength();

                // 🚫 BASELINE FILTER
                if (baseline != null &&
                        status == baseline.status &&
                        Math.abs(length - baseline.contentLength) < 50) {
                    continue; // looks like fake response
                }

                if (status == 200 || status == 301 ||
                        status == 302 || status == 401 || status == 403) {

                    results.add(new DirectoryScanResult(word, status));
                }

            } catch (Exception ignored) {}
        }

        return results;
    }
    private BaselineResponse getBaseline(String baseUrl) {

        try {
            String randomPath = "/__nonexistent__" + System.nanoTime();
            URL url = new URL(baseUrl + randomPath);

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(2000);
            conn.setInstanceFollowRedirects(false);

            int status = conn.getResponseCode();
            int length = conn.getContentLength();

            return new BaselineResponse(status, length);

        } catch (Exception e) {
            return null;
        }
    }
}
