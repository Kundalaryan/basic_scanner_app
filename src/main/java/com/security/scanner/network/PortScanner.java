package com.security.scanner.network;

import com.security.scanner.model.PortScanResult;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class PortScanner {

    private static final int TIMEOUT = 1500;
    private final BannerGrabber bannerGrabber = new BannerGrabber();

    public List<PortScanResult> scan(String host, List<Integer> ports) {

        List<PortScanResult> results = new ArrayList<>();

        for (int port : ports) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), TIMEOUT);

                String banner = bannerGrabber.grab(host, port);
                results.add(new PortScanResult(port, banner));

            } catch (Exception ignored) {
                // Port closed
            }
        }
        return results;
    }
}
