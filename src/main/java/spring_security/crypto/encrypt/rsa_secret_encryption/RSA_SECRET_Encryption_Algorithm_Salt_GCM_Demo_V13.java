package spring_security.crypto.encrypt.rsa_secret_encryption;

import org.springframework.security.crypto.encrypt.RsaAlgorithm;
import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_SECRET_Encryption_Algorithm_Salt_GCM_Demo_V13
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates:
 * RsaSecretEncryptor(RsaAlgorithm algorithm,String salt,boolean gcm)
 * ==========================================================================================
 * CORE IDEA
 * ==========================================================================================
 * This constructor provides:
 * ✔ Control over RSA padding (algorithm)
 * ✔ Control over AES mode (GCM / CBC)
 * ✔ Control over salt (entropy input)
 * ✔ Internal key management (no KeyPair provided)
 * ==========================================================================================
 * KEY CHARACTERISTIC
 * ==========================================================================================
 * Unlike V11 (PublicKey) or V9 (KeyPair):
 * ❗ Keys are internally generated/managed
 * Therefore:
 * ✔ Encryption works
 * ✔ Decryption works ONLY within SAME instance
 * ❌ Not portable across systems
 * ==========================================================================================
 * ALGORITHM DETAILS
 * ==========================================================================================
 * Using:
 * RsaAlgorithm.OAEP
 * Maps to:
 * RSA/ECB/OAEPWithSHA-1AndMGF1Padding
 * ==========================================================================================
 * GCM MODE (IMPORTANT)
 * ==========================================================================================
 * true → AES-GCM (Authenticated Encryption)
 * Provides:
 * ✔ Confidentiality
 * ✔ Integrity (authentication tag)
 * If ciphertext is modified:
 * → AEADBadTagException during decryption
 * ==========================================================================================
 * SALT ROLE
 * ==========================================================================================
 * • Adds entropy to encryption context
 * • Helps avoid predictable patterns
 * CRITICAL:
 * Must be SAME during decryption
 * ==========================================================================================
 * INTERNAL HYBRID FLOW
 * ==========================================================================================
 * 1) Internal RSA KeyPair used
 * 2) AES key generated
 * 3) AES encrypts data (GCM/CBC)
 * 4) RSA encrypts AES key
 * 5) Combined ciphertext returned
 * ==========================================================================================
 * LIMITATION
 * ==========================================================================================
 * ❌ Cannot share ciphertext across different instances
 * ==========================================================================================
 * USE CASE
 * ==========================================================================================
 * ✔ Secure internal processing
 * ✔ Temporary encryption
 * ✔ Same-JVM workflows
 */
public class RSA_SECRET_Encryption_Algorithm_Salt_GCM_Demo_V13 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_Algorithm_Salt_GCM_Demo_V13.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA ALGORITHM + SALT + GCM DEMO V13 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: CONFIGURATION
            // ==================================================================================
            // RSA Algorithm (OAEP with SHA-1 padding)
            RsaAlgorithm algorithm = RsaAlgorithm.OAEP;

            // Salt (must remain same for decryption)
            String salt = "v13SecureSaltValue!";

            // AES Mode (true = GCM, false = CBC)
            boolean useGCM = true;

            logger.info("Algorithm: " + algorithm);
            logger.info("Salt: " + salt);
            logger.info("GCM Enabled: " + useGCM);

            // ==================================================================================
            // STEP 2: INITIALIZE ENCRYPTOR
            // ==================================================================================
            // Internally handles:
            //   • RSA KeyPair lifecycle
            //   • AES key generation
            //
            RsaSecretEncryptor encryptor = new RsaSecretEncryptor(algorithm, salt, useGCM);

            logger.info("Encryptor initialized (Algorithm + Salt + GCM).");

            // ==================================================================================
            // STEP 3: PREPARE DATA
            // ==================================================================================
            String data = "RSA Algorithm + Salt + GCM Demo (V13)";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);

            // ==================================================================================
            // STEP 4: ENCRYPT
            // ==================================================================================
            byte[] encrypted = encryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            // ==================================================================================
            // STEP 5: DECRYPT (SAME INSTANCE ONLY)
            // ==================================================================================
            byte[] decrypted = encryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted: " + decryptedText);

            // ==================================================================================
            // STEP 6: VERIFY
            // ==================================================================================
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check: " + isMatch);
            logger.info("========== RSA DEMO V13 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            // Possible Issues:
            // • AEADBadTagException → GCM integrity failure
            // • BadPaddingException → RSA mismatch
            // • IllegalStateException → wrong instance usage
            logger.log(Level.SEVERE, "Error in RSA Algorithm + Salt + GCM Demo V13", ex);
        }
    }
}