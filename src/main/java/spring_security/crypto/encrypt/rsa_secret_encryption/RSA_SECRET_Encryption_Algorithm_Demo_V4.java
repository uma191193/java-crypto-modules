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
 * RSA_SECRET_Encryption_Algorithm_Demo_V4
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaSecretEncryptor(String encoding,PublicKey publicKey,PrivateKey privateKey,RsaAlgorithm algorithm)
 * ------------------------------------------------------------------
 * WHAT IS NEW IN V4?
 * ------------------------------------------------------------------
 * ✔ Explicit control over RSA padding/algorithm
 * ✔ Ability to choose secure vs legacy modes
 * ------------------------------------------------------------------
 * SUPPORTED RSA ALGORITHMS (Spring Security)
 * ------------------------------------------------------------------
 * 1) RsaAlgorithm.DEFAULT
 * → Typically maps to RSA/ECB/PKCS1Padding
 * → Widely supported but considered legacy
 * 2) RsaAlgorithm.OAEP
 * → RSA/ECB/OAEPWithSHA-1AndMGF1Padding
 * → More secure than PKCS#1 v1.5
 * 3) RsaAlgorithm.OAEP_256
 * → RSA/ECB/OAEPWithSHA-256AndMGF1Padding
 * → Strongest and recommended
 * ------------------------------------------------------------------
 * CORE ARCHITECTURE (HYBRID ENCRYPTION)
 * ------------------------------------------------------------------
 * 1) Generate random AES key
 * 2) Encrypt plaintext using AES (fast, scalable)
 * 3) Encrypt AES key using RSA (selected algorithm)
 * 4) Combine → final ciphertext
 * ------------------------------------------------------------------
 * WHY ALGORITHM MATTERS
 * ------------------------------------------------------------------
 * RSA padding affects:
 * ✔ Security strength
 * ✔ Resistance to attacks (e.g., padding oracle)
 * ✔ Compatibility across systems
 * ------------------------------------------------------------------
 * RECOMMENDATION
 * ------------------------------------------------------------------
 * ✔ Use OAEP_256 for modern secure applications
 * ❌ Avoid DEFAULT in new systems
 */
public class RSA_SECRET_Encryption_Algorithm_Demo_V4 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_Algorithm_Demo_V4.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA SECRET ALGORITHM DEMO V4 STARTED ==========");
        try {
            //----------------------------------------------------------
            // STEP 1: GENERATE RSA KEY PAIR
            //----------------------------------------------------------
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            logger.info("RSA KeyPair generated (2048-bit).");

            //----------------------------------------------------------
            // STEP 2: SELECT RSA ALGORITHM (CRITICAL STEP)
            //----------------------------------------------------------
            // Choose one:
            // RsaAlgorithm.DEFAULT  → PKCS#1 v1.5 (legacy)
            // RsaAlgorithm.OAEP     → SHA-1 based OAEP
            // RsaAlgorithm.OAEP_256 → SHA-256 based OAEP (recommended)

            RsaAlgorithm algorithm = RsaAlgorithm.OAEP;
            logger.info("Selected RSA Algorithm: " + algorithm);

            //----------------------------------------------------------
            // STEP 3: INITIALIZE ENCRYPTOR
            //----------------------------------------------------------
            // encoding = UTF-8 ensures consistent byte conversion
            // publicKey  → used for encrypting AES key
            // privateKey → used for decrypting AES key
            // algorithm  → defines RSA padding scheme

            RsaSecretEncryptor rsaSecretEncryptor = new RsaSecretEncryptor("UTF-8", keyPair.getPublic(),
                    keyPair.getPrivate(), algorithm);
            logger.info("Encryptor initialized with algorithm: " + algorithm);
            //----------------------------------------------------------
            // STEP 4: PREPARE PLAINTEXT
            //----------------------------------------------------------
            String data = "RSA Secret Encryptor V4 (Algorithm Control)";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);
            //----------------------------------------------------------
            // STEP 5: ENCRYPT
            //----------------------------------------------------------
            // Internally:
            // • AES encrypts data
            // • RSA (selected algorithm) encrypts AES key

            byte[] encrypted = rsaSecretEncryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            //----------------------------------------------------------
            // STEP 6: DECRYPT
            //----------------------------------------------------------
            // Reverse flow:
            // • RSA decrypts AES key (using same algorithm)
            // • AES decrypts data
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
            logger.info("========== RSA SECRET DEMO V4 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible failures:
            //
            // • Unsupported algorithm in JVM
            // • Mismatched encryption/decryption algorithm
            // • Invalid key pair
            // • Cipher initialization issues
            //
            logger.log(Level.SEVERE, "Error in RSA Secret Encryptor V4 demo", ex);
        }
    }
}