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
 * RSA_RAW_Encryption_KeyPair_Demo_V8
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaRawEncryptor(KeyPair keyPair)
 * ------------------------------------------------------------------
 * WHY THIS CONSTRUCTOR?
 * ------------------------------------------------------------------
 * ✔ Simplifies initialization (single object instead of 2 keys)
 * ✔ Cleaner API for internal key handling
 * ✔ Useful when key pair is already available
 * ------------------------------------------------------------------
 * INTERNAL BEHAVIOR
 * ------------------------------------------------------------------
 * • Extracts:
 * - PublicKey  → for encryption
 * - PrivateKey → for decryption
 * • Uses default algorithm:
 * → RSA/ECB/PKCS1Padding (PKCS#1 v1.5)
 * ------------------------------------------------------------------
 * FLOW
 * ------------------------------------------------------------------
 * 1) Generate RSA KeyPair
 * 2) Initialize encryptor using KeyPair
 * 3) Encrypt plaintext
 * 4) Decrypt ciphertext
 * 5) Verify integrity
 * ------------------------------------------------------------------
 * IMPORTANT NOTES
 * ------------------------------------------------------------------
 * ✔ Works for small payloads only
 * ❌ Not OAEP (less secure than V7)
 * ❌ Not suitable for large data
 * ------------------------------------------------------------------
 * RECOMMENDED USAGE
 * ------------------------------------------------------------------
 * ✔ Internal systems
 * ✔ Legacy integrations
 * Prefer:
 * ✔ V7 (OAEP)
 * ✔ Hybrid Encryption (AES + RSA)
 */
public class RSA_RAW_Encryption_KeyPair_Demo_V8 {

    private static final Logger logger = Logger.getLogger(RSA_RAW_Encryption_KeyPair_Demo_V8.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA RAW KEYPAIR DEMO V8 STARTED ==========");
        try {
            //----------------------------------------------------------
            // STEP 1: GENERATE RSA KEY PAIR
            //----------------------------------------------------------
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            logger.info("RSA KeyPair generated.");
            //----------------------------------------------------------
            // STEP 2: INITIALIZE ENCRYPTOR USING KEYPAIR
            //----------------------------------------------------------
            // Internally extracts public/private keys
            RsaRawEncryptor encryptor = new RsaRawEncryptor(keyPair);
            logger.info("Encryptor initialized using KeyPair.");
            //----------------------------------------------------------
            // STEP 3: PREPARE DATA
            //----------------------------------------------------------
            String data = "RSA KeyPair Constructor Demo V8";
            Objects.requireNonNull(data);
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);
            //----------------------------------------------------------
            // STEP 4: ENCRYPT
            //----------------------------------------------------------
            byte[] encrypted = encryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);
            //----------------------------------------------------------
            // STEP 5: DECRYPT
            //----------------------------------------------------------
            byte[] decrypted = encryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted: " + decryptedText);
            //----------------------------------------------------------
            // STEP 6: VERIFY
            //----------------------------------------------------------
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check: " + isMatch);
            if (!isMatch) {
                logger.warning("Data mismatch detected!");
            }
            logger.info("========== RSA RAW KEYPAIR DEMO V8 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible issues:
            // • Key generation failure
            // • Data size too large for RSA
            // • Decryption issues (if key corrupted)
            //----------------------------------------------------------
            logger.log(Level.SEVERE, "Error in RSA KeyPair Demo V8", ex);
        }
    }
}