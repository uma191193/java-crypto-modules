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
 * RSA_SECRET_Encryption_Advanced_Demo_V5
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaSecretEncryptor(String encoding,PublicKey publicKey,PrivateKey privateKey,
 * RsaAlgorithm algorithm,String salt,boolean gcm)
 * ------------------------------------------------------------------
 * WHAT IS NEW IN V5?
 * ------------------------------------------------------------------
 * ✔ Salt support (adds randomness / strengthens AES key handling)
 * ✔ GCM mode support (authenticated encryption)
 * ------------------------------------------------------------------
 * CORE ARCHITECTURE (HYBRID ENCRYPTION)
 * ------------------------------------------------------------------
 * 1) AES key handling (with salt influence)
 * 2) AES encryption (CBC or GCM based on flag)
 * 3) RSA encrypts AES key (using selected algorithm)
 * 4) Combine → final ciphertext
 * ------------------------------------------------------------------
 * GCM vs CBC
 * ------------------------------------------------------------------
 * ✔ GCM (gcm = true)
 * → Provides confidentiality + integrity (AEAD)
 * → Protects against tampering
 * ✔ CBC (gcm = false)
 * → Only confidentiality
 * → Requires separate integrity mechanism
 * ------------------------------------------------------------------
 * SALT ROLE
 * ------------------------------------------------------------------
 * • Adds additional randomness
 * • Helps prevent pattern reuse
 * • Should be consistent for decrypting same data
 * ------------------------------------------------------------------
 * RECOMMENDED SETTINGS
 * ------------------------------------------------------------------
 * ✔ algorithm = OAEP_256
 * ✔ gcm = true
 * ✔ strong random salt
 */
public class RSA_SECRET_Encryption_Advanced_Demo_V5 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_Advanced_Demo_V5.class.getName());

    public static void main(String[] args) {
        logger.info("========== RSA SECRET ADVANCED DEMO V5 STARTED ==========");
        try {
            //----------------------------------------------------------
            // STEP 1: GENERATE RSA KEY PAIR
            //----------------------------------------------------------
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            logger.info("RSA KeyPair generated (2048-bit).");

            //----------------------------------------------------------
            // STEP 2: CONFIGURE ADVANCED PARAMETERS
            //----------------------------------------------------------
            RsaAlgorithm algorithm = RsaAlgorithm.OAEP;

            // Salt should ideally come from secure random source
            String salt = "a1b2c3d4e5f6g7h8";

            // Enable GCM (recommended)
            boolean useGCM = true;

            logger.info("Algorithm: " + algorithm);
            logger.info("GCM Enabled: " + useGCM);
            logger.info("Salt: " + salt);

            //----------------------------------------------------------
            // STEP 3: INITIALIZE ENCRYPTOR
            //----------------------------------------------------------
            RsaSecretEncryptor rsaSecretEncryptor = new RsaSecretEncryptor("UTF-8", keyPair.getPublic(),
                    keyPair.getPrivate(), algorithm, salt, useGCM);

            logger.info("Encryptor initialized with advanced configuration.");

            //----------------------------------------------------------
            // STEP 4: PREPARE DATA
            //----------------------------------------------------------
            String data = "RSA Secret Encryptor V5 (Advanced Mode)";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);

            //----------------------------------------------------------
            // STEP 5: ENCRYPT
            //----------------------------------------------------------
            // Internals:
            // • AES encryption (GCM mode)
            // • RSA encrypts AES key (OAEP-256)
            // • Authentication tag added (GCM)

            byte[] encrypted = rsaSecretEncryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            //----------------------------------------------------------
            // STEP 6: DECRYPT
            //----------------------------------------------------------
            // Internals:
            // • RSA decrypts AES key
            // • AES-GCM verifies integrity (auth tag)
            // • Decrypts data

            byte[] decrypted = rsaSecretEncryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted: " + decryptedText);

            //----------------------------------------------------------
            // STEP 7: VERIFY INTEGRITY
            //----------------------------------------------------------
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check: " + isMatch);
            if (!isMatch) {
                logger.warning("Data mismatch detected!");
            }
            logger.info("========== RSA SECRET DEMO V5 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible failures:
            //
            // • GCM authentication failure (tampered data)
            // • Algorithm mismatch
            // • Incorrect salt usage
            // • Invalid key pair
            //
            logger.log(Level.SEVERE, "Error in RSA Secret Encryptor V5 demo", ex);
        }
    }
}