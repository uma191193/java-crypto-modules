package spring_security.crypto.encrypt.rsa_raw_encryption;

import org.springframework.security.crypto.encrypt.RsaAlgorithm;
import org.springframework.security.crypto.encrypt.RsaRawEncryptor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_RAW_Encryption_AlgorithmOnly_Demo_V11
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of:
 * RsaRawEncryptor(RsaAlgorithm algorithm)
 * ------------------------------------------------------------------
 * CORE IDEA
 * ------------------------------------------------------------------
 * ✔ Automatically generates RSA KeyPair internally
 * ✔ Allows explicit control over encryption algorithm (OAEP / DEFAULT)
 * ------------------------------------------------------------------
 * DIFFERENCE FROM V4
 * ------------------------------------------------------------------
 * V4: → Default constructor (no control)
 * V11: → Algorithm control (secure upgrade)
 * ------------------------------------------------------------------
 * SUPPORTED ALGORITHMS
 * ------------------------------------------------------------------
 * • RsaAlgorithm.DEFAULT → PKCS#1 v1.5 (legacy)
 * • RsaAlgorithm.OAEP    → Recommended (secure)
 * ------------------------------------------------------------------
 * INTERNAL BEHAVIOR
 * ------------------------------------------------------------------
 * Internally performs:
 * 1) Generates RSA KeyPair (2048-bit typically)
 * 2) Configures Cipher with selected padding
 * Example: OAEP → RSA/ECB/OAEPWithSHA-1AndMGF1Padding
 * ------------------------------------------------------------------
 * USE CASE
 * ------------------------------------------------------------------
 * ✔ Quick demos
 * ✔ Testing encryption behavior
 * ❌ NOT recommended for production:
 * • No control over key persistence
 * • Keys lost after object lifecycle
 */
public class RSA_RAW_Encryption_AlgorithmOnly_Demo_V11 {

    private static final Logger logger = Logger.getLogger(RSA_RAW_Encryption_AlgorithmOnly_Demo_V11.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA ALGORITHM-ONLY DEMO V11 STARTED ==========");
        try {
            //----------------------------------------------------------
            // STEP 1: INITIALIZE ENCRYPTOR WITH ALGORITHM ONLY
            //----------------------------------------------------------
            // Internally:
            // • Generates RSA KeyPair
            // • Applies OAEP padding
            // 🔐 Recommended: Use OAEP
            RsaRawEncryptor rsaRawEncryptor = new RsaRawEncryptor(RsaAlgorithm.OAEP);
            logger.info("Encryptor initialized with OAEP algorithm (auto-generated keys).");
            //----------------------------------------------------------
            // STEP 2: PREPARE DATA
            //----------------------------------------------------------
            String data = "RSA Algorithm Only Demo V11";
            Objects.requireNonNull(data);
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);
            logger.info("Plaintext Length: " + plaintext.length + " bytes");
            //----------------------------------------------------------
            // STEP 3: ENCRYPT
            //----------------------------------------------------------
            byte[] encrypted = rsaRawEncryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted Length: " + encrypted.length + " bytes");
            logger.info("Encrypted (Base64): " + base64Cipher);
            //----------------------------------------------------------
            // STEP 4: DECRYPT
            //----------------------------------------------------------
            // Works because:
            // ✔ Same object holds private key internally
            byte[] decrypted = rsaRawEncryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted: " + decryptedText);
            //----------------------------------------------------------
            // STEP 5: VERIFY
            //----------------------------------------------------------
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check: " + isMatch);
            if (!isMatch) {
                logger.warning("Data mismatch detected!");
            }
            //----------------------------------------------------------
            // IMPORTANT NOTE
            //----------------------------------------------------------
            // Each new instance: new RsaRawEncryptor(RsaAlgorithm.OAEP) → generates NEW keys
            // So ciphertext from one instance:
            // ❌ CANNOT be decrypted by another instance
            logger.info("========== RSA ALGORITHM-ONLY DEMO V11 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible failures:
            //
            // • IllegalBlockSizeException → Data too large
            // • BadPaddingException → Tampered data
            // • Crypto provider issues
            //----------------------------------------------------------
            logger.log(Level.SEVERE, "Error in Algorithm-Only Demo V11", ex);
        }
    }
}