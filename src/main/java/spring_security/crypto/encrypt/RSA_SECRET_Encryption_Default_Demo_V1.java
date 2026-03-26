package spring_security.crypto.encrypt;

import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_SECRET_Encrypt_Default_Demo_V1
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaSecretEncryptor()
 * ------------------------------------------------------------------
 * WHAT THIS DOES INTERNALLY
 * ------------------------------------------------------------------
 * Hybrid Encryption Model:
 * 1) Generate random AES key
 * 2) Encrypt plaintext using AES
 * 3) Encrypt AES key using RSA
 * 4) Combine → final ciphertext
 * ------------------------------------------------------------------
 * KEY CHARACTERISTICS
 * ------------------------------------------------------------------
 * ✔ No key management required
 * ✔ Supports large data (unlike raw RSA)
 * ✔ Encrypt + Decrypt supported
 * ------------------------------------------------------------------
 * LIMITATIONS
 * ------------------------------------------------------------------
 * ❌ Keys are generated internally
 * ❌ Keys are NOT reusable across instances
 * ❌ Not suitable for distributed systems
 * ------------------------------------------------------------------
 * USE CASE
 * ------------------------------------------------------------------
 * ✔ Learning hybrid encryption
 * ✔ Internal testing
 * ✔ Quick demos
 */
public class RSA_SECRET_Encryption_Default_Demo_V1 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_Default_Demo_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA SECRET DEFAULT DEMO V1 STARTED ==========");
        try {

            //----------------------------------------------------------
            // STEP 1: INITIALIZE ENCRYPTOR (DEFAULT)
            //----------------------------------------------------------
            // Internally:
            // • Generates RSA KeyPair
            // • Configures AES-based encryption
            // ⚠ No control over:
            // • Key storage
            // • Algorithm selection

            RsaSecretEncryptor rsaSecretEncryptor = new RsaSecretEncryptor();

            logger.info("Encryptor initialized (auto-generated keys).");

            //----------------------------------------------------------
            // STEP 2: PREPARE PLAINTEXT
            //----------------------------------------------------------
            String data = "RSA Secret Encryptor Default Demo V1";
            Objects.requireNonNull(data, "Input data must not be null");
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);

            logger.info("Plaintext: " + data);
            logger.info("Plaintext Length: " + plaintext.length + " bytes");

            //----------------------------------------------------------
            // STEP 3: ENCRYPT
            //----------------------------------------------------------
            // Internally:
            // • AES encrypts the data
            // • RSA encrypts the AES key
            byte[] encrypted = rsaSecretEncryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted Length: " + encrypted.length + " bytes");
            logger.info("Encrypted (Base64): " + base64Cipher);
            //----------------------------------------------------------
            // STEP 4: DECRYPT
            //----------------------------------------------------------
            // Works ONLY because:
            // • Same instance holds RSA private key

            byte[] decrypted = rsaSecretEncryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted: " + decryptedText);

            //----------------------------------------------------------
            // STEP 5: VERIFY INTEGRITY
            //----------------------------------------------------------
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check: " + isMatch);
            if (!isMatch) {
                logger.warning("Data mismatch detected!");
            }
            //----------------------------------------------------------
            // IMPORTANT BEHAVIOR DEMO
            //----------------------------------------------------------
            // ❌ This WILL FAIL:
            // RsaSecretEncryptor newEncryptor = new RsaSecretEncryptor();
            // newEncryptor.decrypt(encrypted);
            // Reason: Different RSA key pair
            logger.info("========== RSA SECRET DEFAULT DEMO V1 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible failures:
            // • IllegalBlockSizeException
            // • BadPaddingException
            // • Internal crypto provider issues
            logger.log(Level.SEVERE, "Error in RSA Secret Demo V1", ex);
        }
    }
}