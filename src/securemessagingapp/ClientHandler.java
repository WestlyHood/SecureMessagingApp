package securemessagingapp;

import java.io.IOException;
import java.net.Socket;
import java.util.Map;
import java.util.Base64;

class ClientHandler implements Runnable {

    private Socket clientSocket;
    private Map<String, ClientHandler> clients;
    private Map<String, String> publicKeys;
    private String username;
    private java.io.DataInputStream in;
    private java.io.DataOutputStream out;

    public ClientHandler(Socket socket, Map<String, ClientHandler> clients, Map<String, String> publicKeys) {
        this.clientSocket = socket;
        this.clients = clients;
        this.publicKeys = publicKeys;
        try {
            this.in = new java.io.DataInputStream(clientSocket.getInputStream());
            this.out = new java.io.DataOutputStream(clientSocket.getOutputStream());
        } catch (IOException e) {
            System.err.println("Error creating input/output streams: " + e.getMessage());
        }
    }

    @Override
    public void run() {
        try {
            String requestedUsername = in.readUTF();
            String publicKeyBase64 = in.readUTF();

            synchronized (clients) {
                if (!clients.containsKey(requestedUsername)) {
                    this.username = requestedUsername;
                    clients.put(username, this);
                    publicKeys.put(username, publicKeyBase64);
                    System.out.println(username + " (" + clientSocket.getInetAddress().getHostAddress() + ") has joined.");
                    out.writeUTF("USERNAME_OK");
                } else {
                    out.writeUTF("USERNAME_TAKEN");
                    System.err.println("Username " + requestedUsername + " is already taken. Disconnecting.");
                    cleanup();
                    return;
                }
            }

            while (true) {
                System.out.println("ClientHandler (" + username + "): Inside the message processing loop - waiting for type."); // ADD THIS LINE
                String messageType = in.readUTF();
                System.out.println("ClientHandler (" + username + "): Received message type: " + messageType); // ADD THIS LINE

                if ("SEND_MESSAGE".equals(messageType)) {
                    System.out.println("ClientHandler (" + username + "): Processing SEND_MESSAGE."); // ADD THIS LINE
                    String recipient = in.readUTF();
                    int encryptedAesKeyLength = in.readInt();
                    byte[] encryptedAesKey = new byte[encryptedAesKeyLength];
                    in.readFully(encryptedAesKey);
                    int encryptedMessageLength = in.readInt();
                    byte[] encryptedMessageWithIv = new byte[encryptedMessageLength];
                    in.readFully(encryptedMessageWithIv);

                    System.out.println("Server: Received encrypted message for " + recipient + " from " + username + ". AES Key (Base64): " + Base64.getEncoder().encodeToString(encryptedAesKey) + ", Message (Base64): " + Base64.getEncoder().encodeToString(encryptedMessageWithIv));
                    forwardMessage(recipient, encryptedAesKey, encryptedMessageWithIv);
                } else if ("GET_PUBLIC_KEY".equals(messageType)) {
                    String requestedRecipient = in.readUTF();
                    String recipientPublicKey = publicKeys.get(requestedRecipient);
                    if (recipientPublicKey != null) {
                        out.writeUTF(recipientPublicKey);
                    } else {
                        out.writeUTF(""); // Or some error indicator
                    }
                }
            }

        } catch (IOException e) {
            System.err.println("Client " + username + " disconnected: " + e.getMessage());
            // ... (rest of the catch block) ...
        } finally {
            cleanup();
        }
    }

    public void sendMessage(String sender, byte[] encryptedAesKey, byte[] encryptedMessageWithIv) throws IOException {
        out.writeUTF("RECEIVED_MESSAGE");
        out.writeUTF(sender); // Send the sender's username
        out.writeInt(encryptedAesKey.length);
        out.write(encryptedAesKey);
        out.writeInt(encryptedMessageWithIv.length);
        out.write(encryptedMessageWithIv);
    }

    private void forwardMessage(String recipient, byte[] encryptedAesKey, byte[] encryptedMessageWithIv) {
        synchronized (clients) {
            ClientHandler receiver = clients.get(recipient);
            if (receiver != null) {
                System.out.println("Server: Forwarding message from " + username + " to " + recipient); // ADD THIS LINE
                try {
                    receiver.sendMessage(username, encryptedAesKey, encryptedMessageWithIv);
                } catch (IOException e) {
                    System.err.println("Server: Error forwarding message to " + recipient + ": " + e.getMessage());
                }
            } else {
                System.err.println("Server: Recipient " + recipient + " not found.");
                try {
                    out.writeUTF("RECIPIENT_NOT_FOUND"); // Optionally notify sender
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void cleanup() {
        try {
            if (in != null) in.close();
            if (out != null) out.close();
            if (clientSocket != null) clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}