package securemessagingapp;

import javafx.application.Application;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.ResourceBundle;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import securemessagingapp.SecureMessagingClient.ReceivedEncryptedMessage;

public class SecureMessagingApp extends Application implements Initializable {

    @FXML protected TextField usernameField;
    @FXML protected TextField recipientField;
    @FXML protected TextArea messageInputArea;
    @FXML protected TextArea encryptedMessageArea;
    @FXML protected TextArea decryptedMessageArea;
    @FXML protected ListView<SecureMessagingClient.ReceivedEncryptedMessage> receivedEncryptedListView; // Use ListView
    @FXML protected Button connectButton;
    @FXML protected Button sendButton;
    @FXML protected Button decryptButton; // Added decrypt button

    private SecureMessagingClient client;
    private boolean isConnected = false;

    @Override
    public void start(Stage primaryStage) throws Exception {
        try {
            URL fxmlLocation = SecureMessagingApp.class.getResource("messaging_phase3.fxml");
            if (fxmlLocation == null) {
                System.err.println("FXML file not found!");
                return;
            }
            FXMLLoader loader = new FXMLLoader(fxmlLocation);
            VBox root = loader.load();
            Scene scene = new Scene(root);
            primaryStage.setTitle("Secure Messaging App");
            primaryStage.setScene(scene);
            primaryStage.show();

            SecureMessagingApp controller = loader.getController();
            try {
                controller.client = new SecureMessagingClient(controller);
            } catch (NoSuchAlgorithmException e) {
                System.err.println("Error initializing client: " + e.getMessage());
            }
            controller.sendButton.setDisable(true);
            controller.decryptButton.setDisable(true); // This line causes the error
        } catch (IOException e) {
            System.err.println("Error loading FXML: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        // Initialization logic if needed
    }

    @FXML
    private void handleConnect(javafx.event.ActionEvent event) {
        if (!isConnected) {
            String username = usernameField.getText();
            if (username != null && !username.trim().isEmpty()) {
                try {
                    client.connectToServer(username, "localhost", 12345);
                    isConnected = client.isConnected();
                    if (isConnected) {
                        connectButton.setDisable(true);
                        usernameField.setDisable(true);
                        sendButton.setDisable(false);
                        decryptButton.setDisable(false);

                        PrivateKey privateKey = client.getPrivateKey();
                        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
                        System.out.println(username + ": Private Key (Base64) on Connect: " + privateKeyBase64.substring(0, Math.min(privateKeyBase64.length(), 50)) + "...");
                    }
                } catch (IOException e) {
                    System.err.println("Error connecting to server: " + e.getMessage());
                    appendEncryptedMessage("Connection error: " + e.getMessage());
                }
            } else {
                appendEncryptedMessage("Username cannot be empty.");
            }
        }
    }

    @FXML
    private void handleEncryptAndSend(javafx.event.ActionEvent event) {
        if (isConnected) {
            String recipient = recipientField.getText();
            String message = messageInputArea.getText();
            if (message != null && !message.isEmpty()) {
                client.sendMessage(recipient, message);
                messageInputArea.clear();
            } else {
                appendEncryptedMessage("Message cannot be empty.");
            }
        } else {
            appendEncryptedMessage("Not connected to the server.");
        }
    }

    @FXML
    private void handleDecrypt() {
        ReceivedEncryptedMessage selectedMessage = receivedEncryptedListView.getSelectionModel().getSelectedItem();
        if (selectedMessage != null) {
            byte[] encryptedAesKey = selectedMessage.getEncryptedAesKey();
            byte[] encryptedMessageWithIv = selectedMessage.getEncryptedMessageWithIv();

            System.out.println("handleDecrypt: Encrypted AES Key Length: " + encryptedAesKey.length);
            System.out.println("handleDecrypt: Length of encryptedMessageWithIv: " + encryptedMessageWithIv.length);

            if (encryptedMessageWithIv.length <= 16) {
                decryptedMessageArea.setText("Error: Invalid encrypted message format (too short).");
                return;
            }

            byte[] ivBytes = Arrays.copyOfRange(encryptedMessageWithIv, 0, 16);
            byte[] encryptedMessageBytes = Arrays.copyOfRange(encryptedMessageWithIv, 16, encryptedMessageWithIv.length);
            String ivBase64 = Base64.getEncoder().encodeToString(ivBytes);
            System.out.println("handleDecrypt: Extracted IV (Base64): " + ivBase64);

            try {
                // 1. Decrypt the AES key using the recipient's private key
                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Explicit padding
                rsaCipher.init(Cipher.DECRYPT_MODE, client.getPrivateKey());
                byte[] decryptedAesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
                SecretKey originalAesKey = new SecretKeySpec(decryptedAesKeyBytes, "AES");

                // 2. Decrypt the message using the AES key and IV
                Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aesCipher.init(Cipher.DECRYPT_MODE, originalAesKey, new IvParameterSpec(ivBytes));
                byte[] decryptedMessageBytes = aesCipher.doFinal(encryptedMessageBytes);
                String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
                decryptedMessageArea.setText("Decrypted message from " + selectedMessage.getSender() + ":\n" + decryptedMessage);

            } catch (Exception e) {
                decryptedMessageArea.setText("Decryption error: " + e.getMessage());
                e.printStackTrace();
            }
        } else {
            decryptedMessageArea.setText("No message selected to decrypt.");
        }
    }

    public void appendEncryptedMessage(String message) {
        if (encryptedMessageArea != null) {
            encryptedMessageArea.appendText(message + "\n");
        }
    }

    public void appendReceivedEncryptedMessage(SecureMessagingClient.ReceivedEncryptedMessage message) {
        if (receivedEncryptedListView != null) {
            receivedEncryptedListView.getItems().add(message);
            decryptButton.setDisable(false); // Enable when a message is received
        }
    }

    public void appendDecryptedMessage(String sender, String message) {
        if (decryptedMessageArea != null) {
            decryptedMessageArea.appendText("From " + sender + ": " + message + "\n");
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}