package securemessagingapp;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SecureMessagingClient {

    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private String username;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private volatile String receivedPublicKey;
    private final Object publicKeyLock = new Object();
    @FXML private TextArea encryptedMessageArea;
    @FXML private TextArea decryptedMessageArea;
    @FXML private TextField recipientField;
    @FXML private ListView<ReceivedEncryptedMessage> receivedEncryptedListView; // Added FXML for ListView

    private boolean isConnected = false;
    private final ExecutorService sendExecutor = Executors.newSingleThreadExecutor();
    private final List<ReceivedEncryptedMessage> receivedMessages = new ArrayList<>();
    private SecureMessagingApp controller; // Reference to the controller

    public List<ReceivedEncryptedMessage> getReceivedMessages() {
        return receivedMessages;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public static class ReceivedEncryptedMessage {
        private final String sender;
        private final byte[] encryptedAesKey;
        private final byte[] encryptedMessageWithIv;

        public ReceivedEncryptedMessage(String sender, byte[] encryptedAesKey, byte[] encryptedMessageWithIv) {
            this.sender = sender;
            this.encryptedAesKey = encryptedAesKey;
            this.encryptedMessageWithIv = encryptedMessageWithIv;
        }

        public String getSender() {
            return sender;
        }

        public byte[] getEncryptedAesKey() {
            return encryptedAesKey;
        }

        public byte[] getEncryptedMessageWithIv() {
            return encryptedMessageWithIv;
        }

        @Override
        public String toString() {
            return "From: " + sender + ", Encrypted Data (truncated): " + Base64.getEncoder().encodeToString(Arrays.copyOfRange(encryptedMessageWithIv, 0, Math.min(encryptedMessageWithIv.length, 20))) + "...";
        }
    }

    public SecureMessagingClient(SecureMessagingApp controller) throws NoSuchAlgorithmException {
        this.controller = controller;
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // You can use 2048 or 4096 for stronger keys
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    public boolean isConnected() {
        return isConnected;
    }

    public void connectToServer(String username, String host, int port) throws IOException {
        try {
            this.socket = new Socket(host, port);
            this.in = new DataInputStream(socket.getInputStream());
            this.out = new DataOutputStream(socket.getOutputStream());
            this.username = username;

            // Send username and public key to the server
            out.writeUTF(username);
            out.writeUTF(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

            String response = in.readUTF();
            if ("USERNAME_OK".equals(response)) {
                isConnected = true;
                System.out.println("Connected to server as " + username);
                startMessageListener();
            } else {
                System.err.println("Username taken.");
                throw new IOException("Username taken");
            }

        } catch (IOException e) {
            System.err.println("Error connecting to server: " + e.getMessage());
            throw e;
        }
    }

    public void sendMessage(String recipient, String message) {
        System.out.println("sendMessage method called for recipient: " + recipient + ", message: " + message);
        sendExecutor.submit(() -> {
            try {
                System.out.println("sendMessage: Inside sendExecutor for recipient: " + recipient); // ADD THIS

                // 1. Get recipient's public key from the server
                System.out.println("sendMessage: Calling getRecipientPublicKeyInBackground for " + recipient); // ADD THIS
                String recipientPublicKeyBase64 = getRecipientPublicKeyInBackground(recipient);
                System.out.println("sendMessage: Returned from getRecipientPublicKeyInBackground. Key: " + (recipientPublicKeyBase64 != null ? recipientPublicKeyBase64.substring(0, 20) + "..." : "null")); // ADD THIS

                if (recipientPublicKeyBase64 == null) {
                    Platform.runLater(() -> controller.appendEncryptedMessage("Recipient not found.\n"));
                    return;
                }

                PublicKey recipientPublicKey = getPublicKeyFromString(recipientPublicKeyBase64);
                System.out.println("sendMessage: Got recipientPublicKey."); // ADD THIS

                // 2. Generate a new AES key
                SecretKey aesKey = generateAesKey();
                System.out.println("sendMessage: Generated AES key."); // ADD THIS

                // 3. Generate an IV
                IvParameterSpec ivSpec = generateIv();
                byte[] ivBytes = ivSpec.getIV();
                System.out.println("sendMessage: Generated IV."); // ADD THIS

                // 4. Initialize AES cipher for encryption
                Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
                System.out.println("sendMessage: Initialized AES cipher for encryption."); // ADD THIS

                // 5. Encrypt the message
                byte[] encryptedMessage = aesCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
                System.out.println("sendMessage: Encrypted the message."); // ADD THIS

                // 6. Encrypt the AES key with the recipient's RSA public key
                Cipher rsaCipher = Cipher.getInstance("RSA");
                rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);
                byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
                System.out.println("sendMessage: Encrypted AES key."); // ADD THIS

                // Prepare the message for sending: IV + encrypted message
                byte[] encryptedMessageWithIv = new byte[ivBytes.length + encryptedMessage.length];
                System.arraycopy(ivBytes, 0, encryptedMessageWithIv, 0, ivBytes.length);
                System.arraycopy(encryptedMessage, 0, encryptedMessageWithIv, ivBytes.length, encryptedMessage.length);
                System.out.println("sendMessage: Prepared message with IV."); // ADD THIS

                // 7. Send the message type, recipient, encrypted AES key, and encrypted message
                out.writeUTF("SEND_MESSAGE");
                out.writeUTF(recipient);
                out.writeInt(encryptedAesKey.length);
                out.write(encryptedAesKey);
                out.writeInt(encryptedMessageWithIv.length);
                out.write(encryptedMessageWithIv);
                System.out.println("sendMessage: Sent message data."); // ADD THIS

                Platform.runLater(() -> controller.appendEncryptedMessage("Encrypted message sent to " + recipient + "\n"));

            } catch (final Exception e) {
                System.err.println("Error sending message: " + e.getMessage());
                Platform.runLater(() -> controller.appendEncryptedMessage("Error sending message: " + e.getMessage() + "\n"));
            }
        });
    }


    private String getRecipientPublicKeyInBackground(String recipient) throws IOException {
        out.writeUTF("GET_PUBLIC_KEY");
        out.writeUTF(recipient);
        synchronized (publicKeyLock) {
            receivedPublicKey = null;
            try {
                publicKeyLock.wait(5000); // Wait up to 5 seconds for the key
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
            return receivedPublicKey;
        }
    }

    private PublicKey getPublicKeyFromString(String key) throws Exception {
        byte[] byteKey = Base64.getDecoder().decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(byteKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private SecretKey generateAesKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // Use 256-bit AES key
        return keyGenerator.generateKey();
    }

    private IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new Random().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private void startMessageListener() {
        new Thread(() -> {
            try {
                System.out.println(username + ": Message listener started.");
                while (true) {
                    System.out.println(username + ": Message listener - waiting for message type.");
                    String messageType = in.readUTF();
                    System.out.println(username + ": Received message type: " + messageType);
                    if ("RECEIVED_MESSAGE".equals(messageType)) {
                        String sender = in.readUTF();
                        int encryptedAesKeyLength = in.readInt();
                        byte[] encryptedAesKey = new byte[encryptedAesKeyLength];
                        in.readFully(encryptedAesKey);
                        int encryptedMessageWithIvLength = in.readInt();
                        byte[] encryptedMessageWithIv = new byte[encryptedMessageWithIvLength];
                        in.readFully(encryptedMessageWithIv);

                        System.out.println(username + ": Received encrypted message from " + sender);
                        System.out.println(username + ": Encrypted AES Key Length: " + encryptedAesKeyLength);
                        System.out.println(username + ": Encrypted Message with IV Length: " + encryptedMessageWithIvLength);

                        ReceivedEncryptedMessage encryptedMessage = new ReceivedEncryptedMessage(sender, encryptedAesKey, encryptedMessageWithIv);
                        receivedMessages.add(encryptedMessage);

                        Platform.runLater(() -> {
                            controller.appendReceivedEncryptedMessage(encryptedMessage); // Use the new method
                        });

                    } else if ("RECIPIENT_NOT_FOUND".equals(messageType)){
                        Platform.runLater(() -> controller.appendEncryptedMessage("Recipient not found.\n"));
                    } else if (messageType != null && messageType.startsWith("PUBLIC_KEY:")) {
                        String publicKeyBase64 = messageType.substring("PUBLIC_KEY:".length());
                        synchronized (publicKeyLock) {
                            receivedPublicKey = publicKeyBase64;
                            publicKeyLock.notify();
                        }
                    }
                }
            } catch (IOException e) {
                System.err.println(username + ": Error receiving message: " + e.getMessage());
            }
        }).start();
    }

    public String decryptReceivedMessage(String encryptedText) {
        // This method is no longer used directly for decryption in Phase 3
        return "This method is deprecated. Messages are now decrypted manually.";
    }

    public void closeConnection() {
        try {
            if (socket != null) socket.close();
            if (in != null) in.close();
            if (out != null) out.close();
        } catch (IOException e) {
            System.err.println("Error closing connection: " + e.getMessage());
        }
    }
}