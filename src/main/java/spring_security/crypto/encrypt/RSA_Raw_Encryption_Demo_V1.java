package spring_security.crypto.encrypt;

import org.springframework.security.crypto.encrypt.RsaRawEncryptor;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_Raw_Encryption_Demo_V1
 * ------------------------------------------------------------------
 * This program demonstrates asymmetric encryption and decryption
 * using Spring Security's RsaRawEncryptor.
 * Unlike symmetric encryption (AES), RSA uses a key pair:
 * • Public Key  -> Used for encryption
 * • Private Key -> Used for decryption
 * This eliminates the need to share a secret key beforehand.
 * ------------------------------------------------------------------
 * ENCRYPTION LIFECYCLE
 * ------------------------------------------------------------------
 * 1) RSA Key Pair Generation (JCA) - A mathematically linked public/private key pair is created.
 * 2) Encryptor Initialization - RsaRawEncryptor internally configures RSA cipher operations.
 * 3) Encryption - Plaintext is encrypted using the public key.
 * 4) Decryption - Ciphertext is decrypted using the private key.
 * 5) Integrity Verification - Ensures decrypted output matches original input.
 * 6) Deterministic Behavior Demonstration - Shows that RAW RSA produces identical ciphertext
 * for identical inputs (no randomness involved).
 * ------------------------------------------------------------------
 * CRYPTOGRAPHIC ARCHITECTURE
 * ------------------------------------------------------------------
 * Plaintext
 * │
 * ▼
 * RSA Encryption (Public Key)
 * │
 * ▼
 * Ciphertext
 * │
 * ▼
 * RSA Decryption (Private Key)
 * │
 * ▼
 * Original Plaintext
 * ------------------------------------------------------------------
 * IMPORTANT SECURITY NOTES
 * ------------------------------------------------------------------
 * • This demo uses "RAW" RSA mode:
 * - No padding scheme (e.g., OAEP, PKCS#1 v1.5)
 * - No randomness
 * • Consequences:
 * - Deterministic encryption (same input → same output)
 * - Vulnerable to cryptographic attacks (e.g., chosen-plaintext)
 * • Therefore:
 * ❌ NOT suitable for production use
 * ✔ Intended for demonstration/educational purposes only
 * • Real-world recommendation:
 * Use RSA with OAEP padding:
 * "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
 * ------------------------------------------------------------------
 * ADDITIONAL CONSTRAINTS OF RSA
 * ------------------------------------------------------------------
 * • RSA is NOT designed for large data encryption.
 * • Maximum plaintext size depends on key size:
 * - For 2048-bit key → ~245 bytes (with padding, even less)
 * • Typical real-world pattern:
 * RSA encrypts a symmetric key (AES), AES encrypts the actual data (Hybrid Encryption).
 * ------------------------------------------------------------------
 * IMPLEMENTATION NOTE
 * ------------------------------------------------------------------
 * • Spring Security DOES NOT provide key generation utilities.
 * • We use Java Cryptography Architecture (JCA): java.security.KeyPairGenerator
 */
public class RSA_Raw_Encryption_Demo_V1 {

    private static final Logger logger = Logger.getLogger(RSA_Raw_Encryption_Demo_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA RAW ENCRYPTION DEMO STARTED ==========");

        try {

            //--------------------------------------------------------------
            // STEP 1: GENERATE RSA KEY PAIR (JCA)
            //--------------------------------------------------------------
            // RSA key generation involves:
            //
            // 1) Selecting two large prime numbers
            // 2) Computing modulus (n = p * q)
            // 3) Generating:
            //    • Public Key  (n, e)
            //    • Private Key (n, d)
            // Key size (2048 bits):
            // • Determines security strength
            // • Larger key → stronger security but slower operations

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            logger.info("RSA key pair generated successfully.");

            //--------------------------------------------------------------
            // STEP 2: INITIALIZE RSA ENCRYPTOR
            //--------------------------------------------------------------
            // RsaRawEncryptor is responsible for:
            // • Configuring RSA cipher internally
            // • Handling encryption/decryption operations
            // NOTE:
            // This constructor assumes key material is already configured
            // or managed internally (depending on environment/setup).
            // In most real scenarios, keys should be explicitly provided.

            RsaRawEncryptor rsaEncryptor = new RsaRawEncryptor();

            logger.info("RSA encryptor initialized successfully.");

            //--------------------------------------------------------------
            // STEP 3: PREPARE PLAINTEXT
            //--------------------------------------------------------------
            // Convert human-readable text into byte representation.
            // Why bytes?
            // • Cryptographic algorithms operate on binary data.
            // UTF-8 encoding ensures:
            // • Consistent cross-platform representation
            // • Support for all Unicode characters

            String sensitiveData = "Spring Security RSA RAW Encryption Example 2026";
            Objects.requireNonNull(sensitiveData, "Sensitive data cannot be null");

            byte[] plaintext = sensitiveData.getBytes(StandardCharsets.UTF_8);

            logger.info("Plaintext prepared.");
            logger.info("Plaintext length: " + plaintext.length + " bytes");

            //--------------------------------------------------------------
            // STEP 4: ENCRYPT DATA
            //--------------------------------------------------------------
            // Encryption process:
            // plaintext (bytes)
            //      │
            // RSA mathematical transformation using public key
            //      │
            // ciphertext (bytes)
            //
            // Since RAW RSA is used:
            // • No IV (Initialization Vector)
            // • No randomness
            // • Output is deterministic

            byte[] ciphertext = rsaEncryptor.encrypt(plaintext);

            // Base64 encoding:
            // • Converts binary data into printable string format
            // • Useful for logging, storage, transmission

            String encodedCiphertext =
                    Base64.getEncoder().encodeToString(ciphertext);

            logger.info("Encryption completed successfully.");
            logger.info("Ciphertext (Base64): " + encodedCiphertext);
            logger.info("Ciphertext length: " + ciphertext.length + " bytes");

            //--------------------------------------------------------------
            // STEP 5: DECRYPT DATA
            //--------------------------------------------------------------
            // Reverse operation:
            // ciphertext
            //      │
            // RSA mathematical inverse using private key
            //      │
            // original plaintext bytes

            byte[] decryptedBytes = rsaEncryptor.decrypt(ciphertext);

            String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

            logger.info("Decryption completed successfully.");
            logger.info("Decrypted text: " + decryptedText);

            //--------------------------------------------------------------
            // STEP 6: VERIFY INTEGRITY
            //--------------------------------------------------------------
            // Basic integrity check:
            // • Ensures no corruption during encryption/decryption
            // NOTE:
            // This is NOT cryptographic integrity (like HMAC or AEAD),
            // just a logical equality check.

            boolean integrityCheck = sensitiveData.equals(decryptedText);

            if (integrityCheck) {
                logger.info("Integrity verification: SUCCESS");
            } else {
                logger.warning("Integrity verification: FAILED");
            }

            //--------------------------------------------------------------
            // STEP 7: DEMONSTRATE DETERMINISTIC BEHAVIOR
            //--------------------------------------------------------------
            // Key observation:
            // Encrypting the SAME plaintext again:
            // • Produces SAME ciphertext
            // Reason:
            // • No IV
            // • No random padding
            // Security implication:
            // • Attackers can detect repeated messages

            byte[] ciphertext2 = rsaEncryptor.encrypt(plaintext);
            String encodedCiphertext2 = Base64.getEncoder().encodeToString(ciphertext2);

            logger.info("Second encryption result:");
            logger.info(encodedCiphertext2);

            boolean isSame = encodedCiphertext.equals(encodedCiphertext2);
            logger.info("Ciphertexts are identical (expected): " + isSame);

            logger.info("========== RSA RAW ENCRYPTION DEMO COMPLETED ==========");

        }
        //--------------------------------------------------------------
        // EXCEPTION HANDLING
        //--------------------------------------------------------------
        // Handles:
        // • Invalid inputs (nulls, illegal arguments)
        // • Cryptographic failures
        // • Unexpected runtime issues
        //--------------------------------------------------------------
        catch (IllegalArgumentException ex) {
            logger.log(Level.SEVERE, "Invalid input detected. Please verify arguments.", ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Unexpected system error occurred during RSA workflow.", ex);
        }
    }
}