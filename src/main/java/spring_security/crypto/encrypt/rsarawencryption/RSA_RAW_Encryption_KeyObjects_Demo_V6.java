package spring_security.crypto.encrypt.rsarawencryption;

import org.springframework.security.crypto.encrypt.RsaRawEncryptor;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_RAW_Encryption_KeyObjects_Demo_V6
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaRawEncryptor(String encoding, PublicKey publicKey, PrivateKey privateKey)
 * ------------------------------------------------------------------
 * WHY THIS CONSTRUCTOR?
 * ------------------------------------------------------------------
 * ✔ Full control over key management
 * ✔ No dependency on PEM parsing
 * ✔ Suitable for production-grade systems
 * ------------------------------------------------------------------
 * PARAMETERS EXPLAINED
 * ------------------------------------------------------------------
 * encoding:
 * • Charset used for String ↔ byte conversion
 * • Typically UTF-8
 * publicKey:
 * • Used for encryption
 * privateKey:
 * • Used for decryption
 * • If NULL → decryption will FAIL
 * ------------------------------------------------------------------
 * FLOW
 * ------------------------------------------------------------------
 * 1) Generate RSA key pair
 * 2) Initialize RsaRawEncryptor with keys
 * 3) Encrypt plaintext
 * 4) Decrypt ciphertext
 * 5) Verify integrity
 * ------------------------------------------------------------------
 * IMPORTANT NOTES
 * ------------------------------------------------------------------
 * ✔ Uses RAW RSA (default padding → PKCS#1 v1.5)
 * ❌ Not recommended for large data
 * ❌ Not secure as OAEP
 * ✔ Best use case:
 * • Small secrets
 * • Key wrapping (legacy)
 * ------------------------------------------------------------------
 * RECOMMENDATION
 * ------------------------------------------------------------------
 * Prefer:
 * ✔ RSA-OAEP
 * ✔ Hybrid Encryption (RSA + AES-GCM)
 */
public class RSA_RAW_Encryption_KeyObjects_Demo_V6 {

    private static final Logger logger = Logger.getLogger(RSA_RAW_Encryption_KeyObjects_Demo_V6.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA RAW KEY OBJECTS DEMO V6 STARTED ==========");
        try {

            //----------------------------------------------------------
            // STEP 1: GENERATE RSA KEY PAIR
            //----------------------------------------------------------
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            logger.info("RSA KeyPair generated.");
            //----------------------------------------------------------
            // STEP 2: INITIALIZE ENCRYPTOR
            //----------------------------------------------------------
            // encoding = UTF-8 (recommended standard)
            RsaRawEncryptor encryptor = new RsaRawEncryptor("UTF-8", publicKey, privateKey);
            logger.info("Encryptor initialized with key objects.");
            //----------------------------------------------------------
            // STEP 3: PREPARE DATA
            //----------------------------------------------------------
            String data = "RSA Key Object Constructor Demo V6";
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
            logger.info("========== RSA RAW KEY OBJECTS DEMO V6 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible failures:
            // • Invalid key usage
            // • Missing private key (decrypt fails)
            // • Unsupported encoding
            //----------------------------------------------------------
            logger.log(Level.SEVERE, "Error in RSA Key Objects Demo V6", ex);
        }
    }
}