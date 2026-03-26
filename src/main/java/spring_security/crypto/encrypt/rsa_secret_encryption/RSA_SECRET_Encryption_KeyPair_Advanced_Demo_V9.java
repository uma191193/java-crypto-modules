package spring_security.crypto.encrypt.rsa_secret_encryption;

import org.springframework.security.crypto.encrypt.RsaAlgorithm;
import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_SECRET_Encryption_KeyPair_Advanced_Demo_V9
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates advanced usage of:
 * RsaSecretEncryptor(KeyPair keyPair,RsaAlgorithm algorithm,String salt,boolean gcm)
 * ==========================================================================================
 * IMPORTANT ENVIRONMENT NOTE
 * ==========================================================================================
 * This demo uses:
 * RsaAlgorithm.OAEP
 * Which internally maps to:
 * RSA/ECB/OAEPWithSHA-1AndMGF1Padding
 * WHY NOT OAEP_256?
 * ----------------------------------------------------------
 * • OAEP_256 requires SHA-256 support in the JCE provider
 * • Not all environments (or Spring versions) expose it
 * SECURITY NOTE:
 * ----------------------------------------------------------
 * ✔ OAEP (SHA-1) is STILL SECURE for padding usage
 * ✔ SHA-1 here is used inside MGF1 (not for hashing passwords)
 * ✔ Industry still accepts OAEP-SHA1 for RSA encryption
 * ==========================================================================================
 * HYBRID ENCRYPTION MODEL
 * ==========================================================================================
 * This implementation follows a HYBRID CRYPTOGRAPHIC DESIGN:
 * RSA  → Protects AES key
 * AES  → Encrypts actual data
 * FLOW:
 * Plaintext
 * ↓
 * AES Encryption (GCM or CBC)
 * ↓
 * RSA encrypts AES key (OAEP)
 * ↓
 * Final Ciphertext (combined structure)
 * ==========================================================================================
 * INTERNAL COMPONENTS
 * ==========================================================================================
 * 1) RSA (Asymmetric Layer)
 * • Algorithm: OAEP (SHA-1 + MGF1)
 * • Role: Encrypt AES key only
 * 2) AES (Symmetric Layer)
 * • Role: Encrypt actual payload
 * 3) GCM MODE (if enabled)
 * • Provides:
 * → Confidentiality
 * → Integrity (authentication tag)
 * • Detects tampering during decryption
 * 4) SALT
 * • Adds entropy to encryption context
 * • Must match during decryption
 * ==========================================================================================
 * SECURITY PROPERTIES
 * ==========================================================================================
 * ✔ Confidentiality → AES encryption
 * ✔ Key Security → RSA-OAEP
 * ✔ Integrity → AES-GCM (if enabled)
 * ==========================================================================================
 * CRITICAL DECRYPTION RULES
 * ==========================================================================================
 * 1) SAME KeyPair must be used
 * 2) SAME RsaAlgorithm (OAEP) must be used
 * 3) SAME Salt must be used
 * 4) SAME GCM flag must be used
 * Otherwise:
 * → BadPaddingException
 * → AEADBadTagException (if GCM)
 * → Decryption failure
 */
public class RSA_SECRET_Encryption_KeyPair_Advanced_Demo_V9 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_KeyPair_Advanced_Demo_V9.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA SECRET KEYPAIR ADVANCED DEMO V9 STARTED ==========");

        try {

            // ==================================================================================
            // STEP 1: GENERATE RSA KEY PAIR
            // ==================================================================================
            // RSA key pair consists of:
            //   • PublicKey  → used for encryption
            //   • PrivateKey → used for decryption
            // Key size:
            //   • 2048 bits → industry standard minimum
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            logger.info("RSA KeyPair generated (2048-bit).");

            // ==================================================================================
            // STEP 2: CONFIGURE CRYPTO PARAMETERS
            // ==================================================================================
            // ------------------------------------------------------------------
            // RSA ALGORITHM
            // ------------------------------------------------------------------
            // OAEP → RSA/ECB/OAEPWithSHA-1AndMGF1Padding
            // Internals:
            //   • Uses SHA-1 inside MGF1 (mask generation)
            //   • Introduces randomness in padding
            //   • Prevents deterministic encryption
            RsaAlgorithm algorithm = RsaAlgorithm.OAEP;
            // ------------------------------------------------------------------
            // SALT
            // ------------------------------------------------------------------
            // Adds entropy to encryption context.
            // IMPORTANT:
            //   • Must remain IDENTICAL during decryption
            //   • In production → use SecureRandom-generated value
            String salt = "v9SecureSaltValue!";

            // ------------------------------------------------------------------
            // GCM MODE
            // ------------------------------------------------------------------
            // true  → AES-GCM (Authenticated Encryption)
            // false → AES-CBC (No integrity guarantee)
            // GCM provides:
            //   • Authentication tag
            //   • Tamper detection
            boolean useGCM = true;
            logger.info("Algorithm: " + algorithm);
            logger.info("Salt: " + salt);
            logger.info("GCM Enabled: " + useGCM);

            // ==================================================================================
            // STEP 3: INITIALIZE ENCRYPTOR
            // ==================================================================================
            // Internally handles:
            //   • AES key generation
            //   • RSA encryption of AES key
            //   • AES encryption of payload
            //
            RsaSecretEncryptor encryptor = new RsaSecretEncryptor(keyPair, algorithm, salt, useGCM);
            logger.info("Encryptor initialized.");

            // ==================================================================================
            // STEP 4: PREPARE PLAINTEXT
            // ==================================================================================
            String data = "RSA Secret Encryptor V9 (OAEP Compatible)";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);

            logger.info("Plaintext: " + data);
            // ==================================================================================
            // STEP 5: ENCRYPTION
            // ==================================================================================
            // INTERNAL FLOW:
            // 1) Generate AES key
            // 2) Encrypt plaintext using AES (GCM)
            // 3) Encrypt AES key using RSA-OAEP
            // 4) Combine into final ciphertext
            byte[] encrypted = encryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            // ==================================================================================
            // STEP 6: DECRYPTION
            // ==================================================================================
            // INTERNAL FLOW:
            // 1) RSA decrypt AES key using PrivateKey
            // 2) AES-GCM validates authentication tag
            // 3) If valid → decrypt
            byte[] decrypted = encryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted: " + decryptedText);

            // ==================================================================================
            // STEP 7: VERIFICATION
            // ==================================================================================
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check: " + isMatch);
            logger.info("========== RSA SECRET DEMO V9 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            //
            // Possible Exceptions:
            //
            // • BadPaddingException → RSA mismatch / wrong algorithm
            // • AEADBadTagException → GCM integrity failure
            // • InvalidKeyException → incorrect key usage
            //
            logger.log(Level.SEVERE, "Error in RSA Secret Encryptor V9 demo", ex);
        }
    }
}