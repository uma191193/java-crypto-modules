package spring_security.crypto.encrypt.rsasecretencryption;

import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_SECRET_Encryption_PublicKey_EncryptionOnly_Demo_V10
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates:
 * RsaSecretEncryptor(PublicKey publicKey)
 * This constructor supports:
 * ✔ Encryption ONLY
 * ❌ Decryption NOT possible
 * ==========================================================================================
 * REAL-WORLD USE CASE (CRITICAL)
 * ==========================================================================================
 * This is how real systems work:
 * CLIENT SIDE:
 * • Has ONLY Public Key
 * • Encrypts sensitive data
 * • Sends to server
 * SERVER SIDE:
 * • Holds Private Key (secure)
 * • Decrypts data
 * FLOW:
 * Client → Encrypt (PublicKey)
 * → Send Ciphertext
 * Server → Decrypt (PrivateKey)
 * ==========================================================================================
 * WHY ONLY ENCRYPTION?
 * ==========================================================================================
 * RSA DESIGN:
 * PublicKey  → Encrypt
 * PrivateKey → Decrypt
 * If PrivateKey is NOT provided:
 * → Decryption is impossible by design
 * ==========================================================================================
 * INTERNAL HYBRID ENCRYPTION
 * ==========================================================================================
 * Even here, encryption is NOT pure RSA:
 * 1) AES key is generated
 * 2) Data encrypted using AES
 * 3) AES key encrypted using RSA PublicKey
 * RESULT:
 * Hybrid Ciphertext (AES + RSA wrapped key)
 * ==========================================================================================
 * DEFAULT CONFIGURATION USED
 * ==========================================================================================
 * Since constructor is minimal:
 * • Algorithm → Default (typically RSA-OAEP)
 * • AES Mode → Default (CBC unless configured)
 * • Salt → Internally handled
 * ==========================================================================================
 * SECURITY MODEL
 * ==========================================================================================
 * ✔ Safe for data transmission
 * ✔ Public key can be shared openly
 * ✔ Private key remains secret
 * ==========================================================================================
 * LIMITATION
 * ==========================================================================================
 * ❌ Cannot decrypt using this instance
 * Attempting decrypt():
 * → Will throw exception
 */
public class RSA_SECRET_Encryption_PublicKey_EncryptionOnly_Demo_V10 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_PublicKey_EncryptionOnly_Demo_V10.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA PUBLIC KEY ENCRYPTION DEMO V10 STARTED ==========");

        try {

            // ==================================================================================
            // STEP 1: GENERATE KEY PAIR (SIMULATION PURPOSE)
            // ==================================================================================
            // In real-world:
            //   • Server generates KeyPair
            //   • Shares ONLY PublicKey with clients
            //
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();

            logger.info("PublicKey extracted for encryption.");

            // ==================================================================================
            // STEP 2: INITIALIZE ENCRYPTOR (PUBLIC KEY ONLY)
            // ==================================================================================
            // IMPORTANT:
            //   This encryptor CANNOT decrypt
            //
            RsaSecretEncryptor rsaSecretEncryptor = new RsaSecretEncryptor(publicKey);

            logger.info("Encryptor initialized (Encryption-Only Mode).");

            // ==================================================================================
            // STEP 3: PREPARE DATA
            // ==================================================================================
            String data = "Sensitive Data from Client";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);

            logger.info("Plaintext: " + data);

            // ==================================================================================
            // STEP 4: ENCRYPT
            // ==================================================================================
            byte[] encrypted = rsaSecretEncryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            // ==================================================================================
            // STEP 5: DECRYPT ATTEMPT (EXPECTED FAILURE)
            // ==================================================================================
            try {
                rsaSecretEncryptor.decrypt(encrypted);
                logger.warning("Unexpected: Decryption should NOT succeed!");
            } catch (Exception ex) {
                logger.info("Expected Failure: Cannot decrypt with PublicKey-only encryptor.");
            }

            logger.info("========== RSA PUBLIC KEY ENCRYPTION DEMO V10 COMPLETED ==========");
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Error in RSA PublicKey Encryption Demo V10", ex);
        }
    }
}