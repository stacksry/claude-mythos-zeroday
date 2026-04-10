/**
 * SafeServer.java
 *
 * Glasswing Training Exercise: Fixed version of VulnerableServer.java
 *
 * Fix strategy: Java Serialization Filter (JEP 290 / JDK 9+)
 * - Whitelist ONLY the exact class(es) you expect
 * - Reject everything else before readObject() instantiates it
 *
 * Compile:  javac SafeServer.java
 * Run:      java SafeServer
 */

import java.io.*;
import java.net.*;

public class SafeServer {

    // Safe DTO — no readObject() override, no side effects on deserialization
    static class SafeMessage implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String text;

        public SafeMessage(String text) {
            this.text = text;
        }

        public String getText() { return text; }
    }

    public static void main(String[] args) throws Exception {
        int port = 9998;
        System.out.println("[SAFE SERVER] Listening on port " + port + " (with deserialization filter)");

        try (ServerSocket server = new ServerSocket(port)) {
            while (true) {
                Socket client = server.accept();
                System.out.println("[SAFE SERVER] Connection from " + client.getRemoteSocketAddress());

                ObjectInputStream ois = new ObjectInputStream(client.getInputStream());

                // FIX: Install a serialization filter BEFORE calling readObject()
                // Whitelist only SafeMessage — everything else is rejected
                ois.setObjectInputFilter(filterInfo -> {
                    Class<?> cls = filterInfo.serialClass();
                    if (cls == null) return ObjectInputFilter.Status.ALLOWED; // primitive/array metadata

                    String name = cls.getName();
                    System.out.println("[SAFE SERVER] Filter checking class: " + name);

                    // Whitelist: only our known-safe DTO
                    if (name.equals(SafeServer.class.getName() + "$SafeMessage")) {
                        return ObjectInputFilter.Status.ALLOWED;
                    }

                    // Reject everything else — including gadget chain classes
                    System.out.println("[SAFE SERVER] BLOCKED unauthorized class: " + name);
                    return ObjectInputFilter.Status.REJECTED;
                });

                try {
                    Object obj = ois.readObject();  // filter fires before object is instantiated

                    if (obj instanceof SafeMessage msg) {
                        System.out.println("[SAFE SERVER] Received safe message: " + msg.getText());
                    } else {
                        System.out.println("[SAFE SERVER] Unexpected type, ignoring.");
                    }
                } catch (InvalidClassException | ClassNotFoundException e) {
                    System.out.println("[SAFE SERVER] Deserialization rejected: " + e.getMessage());
                }

                client.close();
            }
        }
    }
}
