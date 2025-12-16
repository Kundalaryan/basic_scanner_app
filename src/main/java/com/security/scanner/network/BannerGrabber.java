package com.security.scanner.network;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class BannerGrabber {

    public String grab(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 2000);
            socket.setSoTimeout(2000);

            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[1024];
            int read = in.read(buffer);

            if (read > 0) {
                String banner = new String(buffer, 0, read, StandardCharsets.UTF_8);
                return banner.replaceAll("\\s+", " ").trim();
            }
        } catch (Exception ignored) {}

        return identifyByPort(port);
    }

    private String identifyByPort(int port) {
        return switch (port) {
            case 21 -> "FTP";
            case 22 -> "SSH";
            case 25 -> "SMTP";
            case 80 -> "HTTP";
            case 443 -> "HTTPS";
            case 3306 -> "MySQL";
            case 8080 -> "HTTP-ALT";
            default -> "Unknown";
        };
    }
}
