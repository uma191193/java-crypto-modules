package spring_security.crypto.encrypt;

import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * AES_Bytes_Encryption_Demo_V1
 * ------------------------------------------------------------------
 * This program demonstrates secure AES encryption and decryption
 * using Spring Security's AesBytesEncryptor.
 * <p>
 * The demonstration walks through the full encryption lifecycle:
 * <p>
 * 1) Password-based key derivation
 * 2) AES encryptor initialization
 * 3) Encryption of plaintext
 * 4) Decryption of ciphertext
 * 5) Integrity verification
 * 6) Demonstration of randomized encryption output
 * <p>
 * ------------------------------------------------------------------
 * CRYPTOGRAPHIC ARCHITECTURE
 * ------------------------------------------------------------------
 * <p>
 * Spring Security internally performs the following operations:
 * <p>
 * Password
 * │
 * ▼
 * PBKDF2 Key Derivation
 * │
 * ▼
 * AES Secret Key
 * │
 * ▼
 * AES/CBC/PKCS5Padding Encryption
 * │
 * ▼
 * Random Initialization Vector (IV)
 * │
 * ▼
 * Ciphertext Output
 * <p>
 * ------------------------------------------------------------------
 * SECURITY PROPERTIES
 * ------------------------------------------------------------------
 * <p>
 * • AES-256 symmetric encryption
 * • Password-based key derivation (PBKDF2)
 * • Random IV generation
 * • Non-deterministic encryption
 * • Protection against rainbow table attacks via salt
 * <p>
 * NOTE:
 * AES encryption is reversible.
 * This is different from password hashing algorithms like Argon2.
 */

public class AES_Bytes_Encryption_Demo_V1 {

    private static final Logger logger = Logger.getLogger(AES_Bytes_Encryption_Demo_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== AES ENCRYPTION DEMO STARTED ==========");
        try {

            //--------------------------------------------------------------
            // STEP 1: DEFINE PASSWORD AND GENERATE SALT
            //--------------------------------------------------------------
            // AES requires a secret key.
            // Instead of storing a raw key, Spring Security derives
            // a key from a password and salt using PBKDF2.
            // Salt properties:
            // • ensures password uniqueness
            // • prevents rainbow table attacks
            // • adds entropy to key derivation

            final String password = "UltraSecureEncryptionPassword2026";
            Objects.requireNonNull(password, "Encryption password cannot be null");
            String salt = KeyGenerators.string().generateKey();
            logger.info("Salt generated successfully.");
            logger.info("Generated salt value: " + salt);

            //--------------------------------------------------------------
            // STEP 2: INITIALIZE AES ENCRYPTOR
            //--------------------------------------------------------------
            // Constructor: AesBytesEncryptor(password, salt)
            // Internal operations:
            // 1) Derive AES key using PBKDF2
            // 2) Configure cipher AES/CBC/PKCS5Padding
            // 3) Prepare secure random IV generator

            AesBytesEncryptor aesBytesEncryptor = new AesBytesEncryptor(password, salt);
            logger.info("AES aesBytesEncryptor successfully initialized.");

            //--------------------------------------------------------------
            // STEP 3: PREPARE PLAINTEXT DATA
            //--------------------------------------------------------------

            String sensitiveData = "Spring Security AES Encryption Example 2026";
            Objects.requireNonNull(sensitiveData, "Sensitive data cannot be null");
            byte[] plaintext = sensitiveData.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext prepared for encryption.");
            logger.info("Plaintext length: " + plaintext.length + " bytes");

            //--------------------------------------------------------------
            // STEP 4: PERFORM ENCRYPTION
            //--------------------------------------------------------------
            // encrypt(byte[])
            // Process:
            // plaintext
            //    │
            // AES encryption with random IV
            //    │
            // ciphertext

            byte[] ciphertext = aesBytesEncryptor.encrypt(plaintext);
            logger.info("Encryption completed successfully.");
            String encodedCiphertext = Base64.getEncoder().encodeToString(ciphertext);
            logger.info("Ciphertext (Base64): " + encodedCiphertext);
            logger.info("Ciphertext length: " + ciphertext.length + " bytes");

            //--------------------------------------------------------------
            // STEP 5: PERFORM DECRYPTION
            //--------------------------------------------------------------
            // decrypt(byte[])
            // Reverse operation:
            // ciphertext
            //     │
            // AES decryption
            //     │
            // original plaintext

            byte[] decryptedBytes = aesBytesEncryptor.decrypt(ciphertext);
            String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
            logger.info("Decryption completed successfully.");
            logger.info("Decrypted text: " + decryptedText);

            //--------------------------------------------------------------
            // STEP 6: VERIFY DATA INTEGRITY
            //--------------------------------------------------------------
            // The decrypted value should match the original plaintext.

            boolean integrityCheck = sensitiveData.equals(decryptedText);
            if (integrityCheck) {
                logger.info("Integrity verification: SUCCESS");
            } else {
                logger.warning("Integrity verification: FAILED");
            }

            //--------------------------------------------------------------
            // STEP 7: DEMONSTRATE NON-DETERMINISTIC ENCRYPTION
            //--------------------------------------------------------------
            // Encrypting the same plaintext again produces a different
            // ciphertext because each encryption uses a random IV.

            byte[] ciphertext2 = aesBytesEncryptor.encrypt(plaintext);
            String encodedCiphertext2 = Base64.getEncoder().encodeToString(ciphertext2);
            logger.info("Second encryption result:");
            logger.info(encodedCiphertext2);
            boolean isDifferent = !encodedCiphertext.equals(encodedCiphertext2);
            logger.info("Ciphertexts are different (expected): " + isDifferent);
            logger.info("========== AES ENCRYPTION DEMO COMPLETED ==========");
        }
        //--------------------------------------------------------------
        // EXCEPTION HANDLING
        //--------------------------------------------------------------
        catch (IllegalArgumentException ex) {
            logger.log(Level.SEVERE, "Invalid input detected. Please verify arguments.", ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Unexpected system error occurred during encryption workflow.", ex);
        }
    }
}
