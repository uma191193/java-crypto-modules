package spring_security.crypto.encrypt.rsa_raw_encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_RAW_Encryption_Hybrid_Demo_V3
 * ------------------------------------------------------------------
 * This program demonstrates a REAL-WORLD encryption architecture:
 * 🔐 HYBRID ENCRYPTION (RSA + AES)
 * Instead of using RSA alone, modern systems combine:
 * • RSA  → Secure key exchange
 * • AES  → Fast data encryption
 * This approach is used in:
 * ✔ HTTPS (TLS)
 * ✔ Secure APIs
 * ✔ Cloud storage encryption
 * ✔ Messaging systems
 * ------------------------------------------------------------------
 * HIGH-LEVEL FLOW
 * ------------------------------------------------------------------
 * SENDER SIDE:
 * 1) Generate AES key (symmetric)
 * 2) Encrypt data using AES-GCM
 * 3) Encrypt AES key using RSA-OAEP (public key)
 * • Encrypted Data (ciphertext)
 * • Encrypted AES Key
 * • IV (Initialization Vector)
 * <p>
 * RECEIVER SIDE:
 * 4) Decrypt AES key using RSA (private key)
 * 5) Decrypt data using AES key
 * ------------------------------------------------------------------
 * CRYPTOGRAPHIC ARCHITECTURE
 * ------------------------------------------------------------------
 * <p>
 * Plaintext
 * │
 * ▼
 * AES-GCM Encryption (using AES key + IV)
 * │
 * ▼
 * Encrypted Data  ─────────────┐
 * │
 * AES Key                     │
 * │                        │
 * ▼                        │
 * RSA-OAEP Encryption         │
 * │                        │
 * ▼                        │
 * Encrypted AES Key ──────────┘
 * <p>
 * Transmission → [Encrypted Data, Encrypted Key, IV]
 * ------------------------------------------------------------------
 * WHY HYBRID ENCRYPTION?
 * ------------------------------------------------------------------
 * RSA:
 * ✔ Secure key distribution
 * ❌ Very slow for large data
 * ❌ Limited input size (~190–214 bytes with OAEP)
 * AES:
 * ✔ Extremely fast
 * ✔ Handles large data efficiently
 * ✔ Supports authenticated encryption (GCM)
 * <p>
 * Combined:
 * ✔ Secure key exchange (RSA)
 * ✔ High-performance data encryption (AES)
 * ✔ Scalable and production-ready
 * ------------------------------------------------------------------
 * AES-GCM (IMPORTANT)
 * ------------------------------------------------------------------
 * AES/GCM/NoPadding provides:
 * • Confidentiality → Data is encrypted
 * • Integrity → Detects tampering
 * • Authentication → Ensures data authenticity
 * GCM produces:
 * • Ciphertext
 * • Authentication Tag (embedded in output)
 * <p>
 * If data is modified:
 * → Decryption FAILS (exception thrown)
 * ------------------------------------------------------------------
 * RSA-OAEP ROLE
 * ------------------------------------------------------------------
 * RSA is ONLY used to encrypt:
 * ✔ AES key (small, fixed size)
 * NOT used for:
 * ❌ Large payload encryption
 * ------------------------------------------------------------------
 * IMPORTANT SECURITY COMPONENTS
 * ------------------------------------------------------------------
 * • AES Key (256-bit)
 * - Symmetric key for data encryption
 * • IV (Initialization Vector)
 * - 12 bytes (recommended for GCM)
 * - Must be unique per encryption
 * • GCM Tag (implicit)
 * - Ensures integrity and authenticity
 * ------------------------------------------------------------------
 * REAL-WORLD TRANSMISSION FORMAT
 * ------------------------------------------------------------------
 * Typically sent as:
 * {
 * "data": Base64(encryptedData),
 * "key" : Base64(encryptedAESKey),
 * "iv"  : Base64(iv)
 * }
 * ------------------------------------------------------------------
 * SECURITY BEST PRACTICES
 * ------------------------------------------------------------------
 * ✔ Always use:
 * - AES-GCM (not CBC)
 * - RSA-OAEP (not RAW)
 * ✔ Never reuse IV with same AES key
 * ✔ Store private keys securely (e.g., HSM, Vault)
 * ✔ Consider key rotation strategies
 * ------------------------------------------------------------------
 * SUMMARY
 * ------------------------------------------------------------------
 * This is the STANDARD pattern used in modern cryptographic systems.
 * If you understand this flow → you understand practical encryption.
 */
public class RSA_RAW_Encryption_Hybrid_Demo_V3 {

    private static final Logger logger = Logger.getLogger(RSA_RAW_Encryption_Hybrid_Demo_V3.class.getName());

    public static void main(String[] args) {

        logger.info("========== HYBRID ENCRYPTION DEMO STARTED ==========");
        try {

            //--------------------------------------------------------------
            // STEP 1: GENERATE RSA KEY PAIR
            //--------------------------------------------------------------
            // RSA keys are used ONLY for encrypting/decrypting AES key.
            // Public Key  → used by sender to encrypt AES key
            // Private Key → used by receiver to decrypt AES key

            KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
            rsaKeyPairGenerator.initialize(2048);
            KeyPair rsaKeyPair = rsaKeyPairGenerator.generateKeyPair();

            //--------------------------------------------------------------
            // STEP 2: GENERATE AES KEY
            //--------------------------------------------------------------
            // AES key is the core encryption key for actual data.
            // 256-bit key:
            // • Strong security
            // • Industry standard

            KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES");
            aesKeyGenerator.init(256);
            SecretKey aesSecretKey = aesKeyGenerator.generateKey();

            logger.info("AES key generated.");

            //--------------------------------------------------------------
            // STEP 3: AES-GCM ENCRYPT DATA
            //--------------------------------------------------------------
            // Steps:
            // 1) Convert plaintext → bytes
            // 2) Generate IV (random, 12 bytes)
            // 3) Initialize AES cipher in GCM mode
            // 4) Encrypt data
            // IV MUST be unique for each encryption with same key.

            String data = "Hybrid Encryption Example (RSA + AES) 2026";
            Objects.requireNonNull(data);

            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);

            byte[] iv = new byte[12]; // 96-bit IV (recommended for GCM)
            new SecureRandom().nextBytes(iv);

            Cipher aesEncryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesEncryptCipher.init(Cipher.ENCRYPT_MODE, aesSecretKey, new GCMParameterSpec(128, iv));

            byte[] encryptedData = aesEncryptCipher.doFinal(plaintext);

            logger.info("Data encrypted using AES-GCM.");

            //--------------------------------------------------------------
            // STEP 4: ENCRYPT AES KEY WITH RSA-OAEP
            //--------------------------------------------------------------
            // AES key (small binary data) is encrypted using RSA.
            // Flow:
            // AES key bytes → RSA encryption → encrypted key

            Cipher rsaEncryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaEncryptCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());

            byte[] encryptedKey = rsaEncryptCipher.doFinal(aesSecretKey.getEncoded());

            logger.info("AES key encrypted using RSA.");

            //--------------------------------------------------------------
            // STEP 5: DECRYPT AES KEY
            //--------------------------------------------------------------
            // Receiver side:
            // Encrypted AES key → RSA decryption → original AES key bytes
            // Reconstruct SecretKey object from raw bytes

            Cipher rsaDecryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaDecryptCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());

            byte[] decryptedKeyBytes = rsaDecryptCipher.doFinal(encryptedKey);

            SecretKey decryptedAesKey = new javax.crypto.spec.SecretKeySpec(decryptedKeyBytes, "AES");

            logger.info("AES key decrypted.");

            //--------------------------------------------------------------
            // STEP 6: DECRYPT DATA
            //--------------------------------------------------------------
            // Reverse AES-GCM process:
            // encryptedData + IV + AES key → original plaintext
            // If data is tampered:
            // → GCM throws authentication exception

            Cipher aesDecryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesDecryptCipher.init(Cipher.DECRYPT_MODE, decryptedAesKey, new GCMParameterSpec(128, iv));

            byte[] decryptedData = aesDecryptCipher.doFinal(encryptedData);
            String result = new String(decryptedData, StandardCharsets.UTF_8);

            logger.info("Decrypted data: " + result);

            //--------------------------------------------------------------
            // STEP 7: VERIFY INTEGRITY
            //--------------------------------------------------------------
            // Logical equality check
            // NOTE:
            // AES-GCM already provides cryptographic integrity

            logger.info("Integrity: " + data.equals(result));

            //--------------------------------------------------------------
            // OUTPUT (TRANSMISSION FORMAT)
            //--------------------------------------------------------------
            // Base64 encoding is used because:
            // • Binary data is not safe for transport/logging
            // • Converts to text-safe representation

            logger.info("Encrypted Payload (Base64):");
            logger.info("Data: " + Base64.getEncoder().encodeToString(encryptedData));
            logger.info("Key: " + Base64.getEncoder().encodeToString(encryptedKey));
            logger.info("IV : " + Base64.getEncoder().encodeToString(iv));

            logger.info("========== HYBRID ENCRYPTION DEMO COMPLETED ==========");

        } catch (Exception ex) {
            //--------------------------------------------------------------
            // EXCEPTION HANDLING
            //--------------------------------------------------------------
            // Covers:
            // • RSA/AES initialization failures
            // • Invalid key usage
            // • GCM authentication failures (tampering)
            //--------------------------------------------------------------
            logger.log(Level.SEVERE, "Hybrid encryption failure", ex);
        }
    }
}