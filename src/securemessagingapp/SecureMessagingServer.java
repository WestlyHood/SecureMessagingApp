package securemessagingapp;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Base64;

public class SecureMessagingServer {

    private static final int PORT = 12345;
    private static Map<String, ClientHandler> clients = new HashMap<>();
    private static Map<String, String> publicKeys = new HashMap<>(); // Username -> Base64 Encoded Public Key
    private static ExecutorService pool = Executors.newFixedThreadPool(10);
    private static final String DB_URL = "jdbc:sqlite:./messaging.db"; // SQLite database file in the project directory

    // Method to establish a database connection
    private static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    // Method to create the messages table if it doesn't exist
    private static void createMessagesTable() {
        String sql = "CREATE TABLE IF NOT EXISTS messages (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "sender_username VARCHAR NOT NULL," +
                "recipient_username VARCHAR NOT NULL," +
                "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP," +
                "encrypted_aes_key BLOB NOT NULL," +
                "encrypted_message_with_iv BLOB NOT NULL" +
                ");";
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Messages table created or already exists.");
        } catch (SQLException e) {
            System.err.println("Error creating messages table: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws IOException {
        createMessagesTable(); // Create the table on server startup
        ServerSocket listener = new ServerSocket(PORT);
        System.out.println("Secure Messaging Server started on port " + PORT);

        while (true) {
            Socket clientSocket = listener.accept();
            System.out.println("Client connected: " + clientSocket.getInetAddress().getHostAddress());
            ClientHandler clientHandler = new ClientHandler(clientSocket, clients, publicKeys);
            pool.execute(clientHandler);
            System.out.println("Submitted ClientHandler to thread pool.");
        }
    }
}

class ClientHandler implements Runnable {

    private Socket clientSocket;
    private Map<String, ClientHandler> clients;
    private Map<String, String> publicKeys;
    private String username;
    private java.io.DataInputStream in;
    private java.io.DataOutputStream out;
    private static final String DB_URL = "jdbc:sqlite:./messaging.db"; // Same DB URL

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

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    private void storeMessage(String sender, String recipient, byte[] encryptedAesKey, byte[] encryptedMessageWithIv) {
        String sql = "INSERT INTO messages (sender_username, recipient_username, encrypted_aes_key, encrypted_message_with_iv) VALUES (?, ?, ?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, sender);
            pstmt.setString(2, recipient);
            pstmt.setBytes(3, encryptedAesKey);
            pstmt.setBytes(4, encryptedMessageWithIv);
            pstmt.executeUpdate();
            System.out.println("Server: Stored message from " + sender + " to " + recipient + " in database.");
        } catch (SQLException e) {
            System.err.println("Error storing message: " + e.getMessage());
        }
    }

    private void deliverAndRemoveOfflineMessages(String recipientUsername) {
        String selectSql = "SELECT sender_username, encrypted_aes_key, encrypted_message_with_iv FROM messages WHERE recipient_username = ?";
        String deleteSql = "DELETE FROM messages WHERE recipient_username = ?";

        try (Connection conn = getConnection();
             PreparedStatement selectStmt = conn.prepareStatement(selectSql);
             PreparedStatement deleteStmt = conn.prepareStatement(deleteSql)) {
            selectStmt.setString(1, recipientUsername);
            ResultSet rs = selectStmt.executeQuery();
            while (rs.next()) {
                String sender = rs.getString("sender_username");
                byte[] encryptedAesKey = rs.getBytes("encrypted_aes_key");
                byte[] encryptedMessageWithIv = rs.getBytes("encrypted_message_with_iv");
                try {
                    System.out.println("Server (Offline): Delivering message from " + sender + " to " + recipientUsername);
                    System.out.println("Server (Offline): Encrypted AES Key Length: " + encryptedAesKey.length + ", Data: " + Base64.getEncoder().encodeToString(encryptedAesKey));
                    System.out.println("Server (Offline): Encrypted Message with IV Length: " + encryptedMessageWithIv.length + ", Data: " + Base64.getEncoder().encodeToString(encryptedMessageWithIv));
                    out.writeUTF("RECEIVED_MESSAGE");
                    out.writeUTF(sender);
                    out.writeInt(encryptedAesKey.length);
                    out.write(encryptedAesKey);
                    out.writeInt(encryptedMessageWithIv.length);
                    out.write(encryptedMessageWithIv);
                    System.out.println("Server: Delivered stored message from " + sender + " to " + recipientUsername + ".");
                } catch (IOException e) {
                    System.err.println("Error sending stored message to " + recipientUsername + ": " + e.getMessage());
                }
            }
            // Delete the delivered messages
            deleteStmt.setString(1, recipientUsername);
            int rowsDeleted = deleteStmt.executeUpdate();
            System.out.println("Server: Deleted " + rowsDeleted + " stored messages for " + recipientUsername + ".");

        } catch (SQLException e) {
            System.err.println("Error retrieving/deleting messages for " + recipientUsername + ": " + e.getMessage());
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
                System.out.println("Server: Received public key for " + username + ": " + publicKeyBase64.substring(0, Math.min(publicKeyBase64.length(), 20)) + "..."); // Added log
                out.writeUTF("USERNAME_OK");
                System.out.println("Server: Checking for offline messages for " + username);
                deliverAndRemoveOfflineMessages(username); // Deliver stored messages on login
            } else {
                out.writeUTF("USERNAME_TAKEN");
                System.err.println("Username " + requestedUsername + " is already taken. Disconnecting.");
                cleanup();
                return;
            }
        }

      while (true) {
        System.out.println("ClientHandler (" + username + "): Inside the message processing loop - waiting for type.");
        String messageType = in.readUTF();
        System.out.println("ClientHandler (" + username + "): Received message type: " + messageType);

        if ("SEND_MESSAGE".equals(messageType)) {
          System.out.println("ClientHandler (" + username + "): Processing SEND_MESSAGE.");
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
          System.out.println("ClientHandler (" + username + "): Received GET_PUBLIC_KEY request.");
          String requestedRecipient = in.readUTF();
          System.out.println("ClientHandler (" + username + "): Requested public key for: " + requestedRecipient);
          String recipientPublicKey = publicKeys.get(requestedRecipient);
          if (recipientPublicKey != null) {
            System.out.println("ClientHandler (" + username + "): Found public key for " + requestedRecipient + ": " + recipientPublicKey.substring(0, 20) + "...");
            out.writeUTF("PUBLIC_KEY:" + requestedRecipient + ":" + recipientPublicKey);
            System.out.println("ClientHandler (" + username + "): Sent public key for " + requestedRecipient + ".");
          } else {
            System.out.println("ClientHandler (" + username + "): Public key not found for " + requestedRecipient + ".");
            out.writeUTF("");
          }
        }
      }

    } catch (IOException e) {
      System.err.println("Client " + username + " disconnected: " + e.getMessage());
      synchronized (clients) {
        clients.remove(username);
        publicKeys.remove(username);
        System.out.println("Client " + username + " disconnected.");
      }
    } finally {
      cleanup();
    }
  }

    public void sendMessage(String sender, byte[] encryptedAesKey, byte[] encryptedMessageWithIv) throws IOException {
        out.writeUTF("RECEIVED_MESSAGE");
        out.writeUTF(sender);
        out.writeInt(encryptedAesKey.length);
        out.write(encryptedAesKey);
        out.writeInt(encryptedMessageWithIv.length);
        out.write(encryptedMessageWithIv);
    }

    private void forwardMessage(String recipient, byte[] encryptedAesKey, byte[] encryptedMessageWithIv) {
        synchronized (clients) {
            ClientHandler receiver = clients.get(recipient);
            if (receiver != null) {
                System.out.println("Server: Forwarding message from " + username + " to " + recipient);
                try {
                    receiver.sendMessage(username, encryptedAesKey, encryptedMessageWithIv);
                } catch (IOException e) {
                    System.err.println("Server: Error forwarding message to " + recipient + ": " + e.getMessage());
                }
            } else {
                System.err.println("Server: Recipient " + recipient + " is offline. About to store message in database.");
                storeMessage(username, recipient, encryptedAesKey, encryptedMessageWithIv);
                System.out.println("Server: Finished storing message for offline recipient " + recipient + ".");
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