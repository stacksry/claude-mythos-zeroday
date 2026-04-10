/**
 * SafeClient.java
 *
 * Sends a legitimate SafeMessage to SafeServer.
 * Try also sending an AttackClient payload to SafeServer — it will be blocked.
 *
 * Compile:  javac SafeClient.java
 * Run:      java SafeClient
 */

import java.io.*;
import java.net.*;

public class SafeClient {

    static class SafeMessage implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String text;

        SafeMessage(String text) { this.text = text; }
        public String getText() { return text; }
    }

    public static void main(String[] args) throws Exception {
        String host = "localhost";
        int port = 9998;

        System.out.println("[SAFE CLIENT] Sending legitimate SafeMessage...");

        try (Socket socket = new Socket(host, port);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {

            oos.writeObject(new SafeMessage("Hello from safe client"));
            oos.flush();
            System.out.println("[SAFE CLIENT] Message sent.");
        }
    }
}
