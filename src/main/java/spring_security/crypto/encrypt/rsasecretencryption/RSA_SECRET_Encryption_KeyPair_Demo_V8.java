package spring_security.crypto.encrypt.rsasecretencryption;

import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_SECRET_Encryption_KeyPair_Demo_V8
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaSecretEncryptor(KeyPair keyPair)
 * ------------------------------------------------------------------
 * WHAT IS NEW IN V8?
 * ------------------------------------------------------------------
 * ✔ Simplified constructor (no manual key extraction)
 * ✔ Cleaner API usage using KeyPair directly
 * ------------------------------------------------------------------
 * INTERNAL BEHAVIOR
 * ------------------------------------------------------------------
 * Equivalent to:
 * new RsaSecretEncryptor("UTF-8",keyPair.getPublic(),keyPair.getPrivate())
 * ------------------------------------------------------------------
 * ENCRYPTION MODEL
 * ------------------------------------------------------------------
 * ✔ Hybrid Encryption:
 * 1) AES encrypts data
 * 2) RSA encrypts AES key
 * ------------------------------------------------------------------
 * KEY USAGE
 * ------------------------------------------------------------------
 * ✔ PublicKey  → Encrypt AES key
 * ✔ PrivateKey → Decrypt AES key
 * ------------------------------------------------------------------
 * ADVANTAGE
 * ------------------------------------------------------------------
 * ✔ Less boilerplate
 * ✔ Reduced chance of key mismatch
 * ✔ Ideal for quick demos and clean codebases
 */
public class RSA_SECRET_Encryption_KeyPair_Demo_V8 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_KeyPair_Demo_V8.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA SECRET KEYPAIR DEMO V8 STARTED ==========");
        try {
            //----------------------------------------------------------
            // STEP 1: GENERATE RSA KEY PAIR
            //----------------------------------------------------------
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            logger.info("RSA KeyPair generated (2048-bit).");

            //----------------------------------------------------------
            // STEP 2: INITIALIZE ENCRYPTOR (KEYPAIR BASED)
            //----------------------------------------------------------
            // Internally extracts:
            // • PublicKey
            // • PrivateKey
            RsaSecretEncryptor rsaSecretEncryptor = new RsaSecretEncryptor(keyPair);
            logger.info("Encryptor initialized using KeyPair.");

            //----------------------------------------------------------
            // STEP 3: PREPARE DATA
            //----------------------------------------------------------
            String data = "RSA Secret Encryptor V8 (KeyPair Constructor)";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);

            //----------------------------------------------------------
            // STEP 4: ENCRYPT
            //----------------------------------------------------------
            byte[] encrypted = rsaSecretEncryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            //----------------------------------------------------------
            // STEP 5: DECRYPT
            //----------------------------------------------------------
            byte[] decrypted = rsaSecretEncryptor.decrypt(encrypted);
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
            logger.info("========== RSA SECRET DEMO V8 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible failures:
            // • KeyPair generation issues
            // • Cipher initialization errors
            // • Unexpected runtime crypto issues
            logger.log(Level.SEVERE, "Error in RSA Secret Encryptor V8 demo", ex);
        }
    }
}
