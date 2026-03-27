package spring_security.crypto.encrypt.rsa_raw_encryption;

import org.springframework.security.crypto.encrypt.RsaRawEncryptor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_RAW_Encryption_Default_Demo_V4
 * ------------------------------------------------------------------
 * PURPOSE
 * ------------------------------------------------------------------
 * Demonstrates basic RSA encryption and decryption using:
 * RsaRawEncryptor()
 * This is the simplest way to use RSA in Spring Security Crypto.
 * ------------------------------------------------------------------
 * WHAT HAPPENS INTERNALLY?
 * ------------------------------------------------------------------
 * When using the default constructor:
 * • A new RSA KeyPair is generated automatically
 * - Public Key  → used for encryption
 * - Private Key → used for decryption
 * • Default transformation is used:
 * - Typically: RSA/ECB/PKCS1Padding
 * ------------------------------------------------------------------
 * FLOW OF EXECUTION
 * ------------------------------------------------------------------
 * 1) Create encryptor
 * 2) Convert plaintext → byte[]
 * 3) Encrypt data using public key
 * 4) Encode ciphertext (Base64)
 * 5) Decrypt using private key
 * 6) Convert decrypted bytes → String
 * 7) Verify result
 * ------------------------------------------------------------------
 * IMPORTANT LIMITATIONS
 * ------------------------------------------------------------------
 * ❌ No control over key generation
 * ❌ Default padding (not OAEP)
 * ❌ Not suitable for large data
 * ❌ Not suitable for production systems
 * ✔ Recommended only for: Learning,Prototyping,Internal demos
 * ------------------------------------------------------------------
 * SECURITY NOTE
 * ------------------------------------------------------------------
 * RSA here provides:
 * ✔ Confidentiality
 * But does NOT guarantee:
 * ❌ Integrity
 * ❌ Authentication
 * For real-world usage:
 * ✔ Use OAEP padding
 * ✔ Use Hybrid Encryption (RSA + AES-GCM)
 */
public class RSA_RAW_Encryption_Default_Demo_V4 {

    private static final Logger logger = Logger.getLogger(RSA_RAW_Encryption_Default_Demo_V4.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA RAW DEFAULT CONSTRUCTOR DEMO V4 STARTED ==========");
        try {

            //----------------------------------------------------------
            // STEP 1: INITIALIZE ENCRYPTOR
            //----------------------------------------------------------
            // This internally generates a new RSA key pair.
            // Same instance must be used for both encrypt & decrypt.

            RsaRawEncryptor rsaRawEncryptor = new RsaRawEncryptor();
            logger.info("RsaRawEncryptor initialized with internally generated key pair.");

            //----------------------------------------------------------
            // STEP 2: PREPARE PLAINTEXT
            //----------------------------------------------------------
            String data = "Default RSA Encryption V4";
            Objects.requireNonNull(data, "Input data must not be null");
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);

            //----------------------------------------------------------
            // STEP 3: ENCRYPT DATA
            //----------------------------------------------------------
            // RSA encryption uses the PUBLIC KEY internally
            byte[] encrypted = rsaRawEncryptor.encrypt(plaintext);

            // Convert to Base64 for readable output
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            //----------------------------------------------------------
            // STEP 4: DECRYPT DATA
            //----------------------------------------------------------
            // RSA decryption uses the PRIVATE KEY internally
            byte[] decrypted = rsaRawEncryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted Text: " + decryptedText);

            //----------------------------------------------------------
            // STEP 5: VERIFY RESULT
            //----------------------------------------------------------
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check (logical): " + isMatch);
            if (!isMatch) {
                logger.warning("Decryption mismatch detected!");
            }
            logger.info("========== RSA RAW DEFAULT DEMO V4 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Covers:
            // • Encryption failures
            // • Decryption failures
            // • Invalid key usage
            //----------------------------------------------------------
            logger.log(Level.SEVERE, "Error during RSA RAW V4 execution", ex);
        }
    }
}