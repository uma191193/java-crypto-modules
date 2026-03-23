package spring_security.crypto.encrypt;

import org.springframework.security.crypto.encrypt.RsaAlgorithm;
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
 * RSA_RAW_Encryption_Algorithm_Demo_V7
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaRawEncryptor(String encoding, PublicKey publicKey,PrivateKey privateKey, RsaAlgorithm algorithm)
 * ------------------------------------------------------------------
 * WHAT'S NEW IN V7?
 * ------------------------------------------------------------------
 * ✔ Explicit algorithm selection
 * ✔ Enables OAEP (modern, secure padding)
 * ------------------------------------------------------------------
 * SUPPORTED ALGORITHMS
 * ------------------------------------------------------------------
 * • RsaAlgorithm.DEFAULT  → PKCS#1 v1.5 (legacy)
 * • RsaAlgorithm.OAEP     → OAEP (recommended)
 * ------------------------------------------------------------------
 * WHY OAEP?
 * ------------------------------------------------------------------
 * ✔ Semantic security (randomized encryption)
 * ✔ Resistant to padding oracle attacks
 * ✔ Used in modern systems (TLS, JWT, etc.)
 * ------------------------------------------------------------------
 * FLOW
 * ------------------------------------------------------------------
 * 1) Generate RSA key pair
 * 2) Initialize encryptor with OAEP
 * 3) Encrypt plaintext
 * 4) Decrypt ciphertext
 * 5) Verify integrity
 * ------------------------------------------------------------------
 * IMPORTANT NOTES
 * ------------------------------------------------------------------
 * ✔ Still RSA → small payload only (~190 bytes)
 * ✔ Not for large data → use Hybrid Encryption
 * ------------------------------------------------------------------
 * SECURITY UPGRADE OVER V6
 * ------------------------------------------------------------------
 * V6 → PKCS#1 v1.5 (less secure)
 * V7 → OAEP (recommended)
 */
public class RSA_RAW_Encryption_Algorithm_Demo_V7 {

    private static final Logger logger = Logger.getLogger(RSA_RAW_Encryption_Algorithm_Demo_V7.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA RAW ALGORITHM DEMO V7 STARTED ==========");
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
            // STEP 2: INITIALIZE ENCRYPTOR WITH ALGORITHM
            //----------------------------------------------------------
            // Choose algorithm:
            // ✔ RsaAlgorithm.OAEP (recommended)
            // ❌ RsaAlgorithm.DEFAULT (legacy)

            //In the below constructor the Parameter RsaAlgorithm.OAEP is important
            RsaRawEncryptor encryptor = new RsaRawEncryptor("UTF-8", publicKey, privateKey, RsaAlgorithm.OAEP);
            logger.info("Encryptor initialized with OAEP algorithm.");

            //----------------------------------------------------------
            // STEP 3: PREPARE DATA
            //----------------------------------------------------------
            String data = "RSA OAEP Encryption Demo V7";
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
            logger.info("========== RSA RAW ALGORITHM DEMO V7 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible failures:
            // • Algorithm mismatch
            // • Invalid key usage
            // • Data too large for RSA
            //----------------------------------------------------------
            logger.log(Level.SEVERE, "Error in RSA Algorithm Demo V7", ex);
        }
    }
}