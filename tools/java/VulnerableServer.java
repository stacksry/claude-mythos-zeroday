/**
 * VulnerableServer.java
 *
 * Glasswing Training Exercise: Java Unsafe Deserialization → RCE
 *
 * Demonstrates the vulnerability class Claude Mythos found in a memory-safe VM monitor:
 * even "safe" languages have exploitable logic bugs.
 *
 * THIS IS FOR EDUCATIONAL / DEFENSIVE PURPOSES ONLY.
 *
 * Compile:  javac VulnerableServer.java
 * Run:      java VulnerableServer
 * Attack:   java AttackClient
 */

import java.io.*;
import java.net.*;

public class VulnerableServer {

    // Simulates a "command" object that gets deserialized from the network
    // In real apps this might be a Job, Task, Message, Event, etc.
    static class RemoteCommand implements Serializable {
        private static final long serialVersionUID = 1L;
        private String command;

        public RemoteCommand(String command) {
            this.command = command;
        }

        // readObject is called automatically by ObjectInputStream.readObject()
        // An attacker can craft a subclass or gadget chain that overrides this
        private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
            ois.defaultReadObject();
            // BUG: blindly executing whatever came off the wire
            System.out.println("[VULN SERVER] Executing deserialized command: " + command);
            Runtime.getRuntime().exec(command);  // RCE — attacker controls 'command'
        }
    }

    public static void main(String[] args) throws Exception {
        int port = 9999;
        System.out.println("[VULN SERVER] Listening on port " + port + " (UNSAFE deserialization)");

        try (ServerSocket server = new ServerSocket(port)) {
            while (true) {
                Socket client = server.accept();
                System.out.println("[VULN SERVER] Connection from " + client.getRemoteSocketAddress());

                // VULNERABILITY: deserializing from untrusted stream with no type filter
                ObjectInputStream ois = new ObjectInputStream(client.getInputStream());
                Object obj = ois.readObject();   // <-- the dangerous line

                System.out.println("[VULN SERVER] Received: " + obj.getClass().getName());
                client.close();
            }
        }
    }
}
