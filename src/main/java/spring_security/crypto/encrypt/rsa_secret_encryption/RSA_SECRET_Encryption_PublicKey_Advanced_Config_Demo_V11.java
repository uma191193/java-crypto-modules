package spring_security.crypto.encrypt.rsa_secret_encryption;

import org.springframework.security.crypto.encrypt.RsaAlgorithm;
import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_SECRET_Encryption_PublicKey_Advanced_Config_Demo_V11
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates:
 * RsaSecretEncryptor(PublicKey publicKey,RsaAlgorithm algorithm,String salt,boolean gcm)
 * ==========================================================================================
 * CORE IDEA (ENCRYPTION-ONLY WITH FULL CONTROL)
 * ==========================================================================================
 * This constructor provides:
 * ✔ PublicKey-only encryption (no decryption capability)
 * ✔ Explicit RSA padding control (OAEP)
 * ✔ Explicit AES mode (GCM / CBC)
 * ✔ Explicit salt control
 * ==========================================================================================
 * REAL-WORLD ARCHITECTURE
 * ==========================================================================================
 * CLIENT (this demo)
 * -------------------
 * • Has PublicKey
 * • Encrypts data
 * • Sends ciphertext
 * ↓
 * SERVER (separate system)
 * ------------------------
 * • Has PrivateKey
 * • Uses matching config
 * • Decrypts data
 * ==========================================================================================
 * HYBRID ENCRYPTION FLOW
 * ==========================================================================================
 * 1) Generate AES key
 * 2) AES encrypts plaintext (GCM/CBC)
 * 3) RSA encrypts AES key (OAEP)
 * 4) Combine → final ciphertext
 * ==========================================================================================
 * ALGORITHM DETAILS
 * ==========================================================================================
 * Using:
 * RsaAlgorithm.OAEP
 * Maps to:
 * RSA/ECB/OAEPWithSHA-1AndMGF1Padding
 * SECURITY NOTE:
 * ✔ SHA-1 here is used inside MGF1 (padding), not hashing user data
 * ✔ Still considered secure in OAEP context
 * ==========================================================================================
 * GCM MODE
 * ==========================================================================================
 * true → AES-GCM (Authenticated Encryption)
 * Provides:
 * ✔ Confidentiality
 * ✔ Integrity (authentication tag)
 * If tampered:
 * → AEADBadTagException during decryption (server-side)
 * ==========================================================================================
 * SALT
 * ==========================================================================================
 * • Adds entropy to encryption context
 * • MUST match on server side for decryption
 * ==========================================================================================
 * LIMITATION
 * ==========================================================================================
 * ❌ Cannot decrypt (no PrivateKey)
 * ==========================================================================================
 * SERVER REQUIREMENT (CRITICAL)
 * ==========================================================================================
 * Server MUST use:
 * same KeyPair (with PrivateKey)
 * same algorithm (OAEP)
 * same salt
 * same gcm flag
 */
public class RSA_SECRET_Encryption_PublicKey_Advanced_Config_Demo_V11 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_PublicKey_Advanced_Config_Demo_V11.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA PUBLIC KEY ADVANCED CONFIG DEMO V11 STARTED ==========");

        try {

            // ==================================================================================
            // STEP 1: GENERATE KEYPAIR (SIMULATION)
            // ==================================================================================
            // In real-world:
            //   • Server generates KeyPair
            //   • Client receives ONLY PublicKey
            //
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();

            logger.info("PublicKey ready for client-side encryption.");

            // ==================================================================================
            // STEP 2: CONFIGURATION
            // ==================================================================================

            // RSA Padding (OAEP with SHA-1)
            RsaAlgorithm algorithm = RsaAlgorithm.OAEP;

            // Salt (must match server)
            String salt = "v11SecureSaltValue!";

            // AES Mode
            boolean useGCM = true;

            logger.info("Algorithm: " + algorithm);
            logger.info("Salt: " + salt);
            logger.info("GCM Enabled: " + useGCM);

            // ==================================================================================
            // STEP 3: INITIALIZE ENCRYPTOR
            // ==================================================================================
            RsaSecretEncryptor encryptor = new RsaSecretEncryptor(publicKey, algorithm, salt, useGCM);
            logger.info("Encryptor initialized (PublicKey + Advanced Config).");

            // ==================================================================================
            // STEP 4: PREPARE DATA
            // ==================================================================================
            String data = "Sensitive Client Payload (V11 Advanced)";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);

            // ==================================================================================
            // STEP 5: ENCRYPT
            // ==================================================================================
            // INTERNAL:
            //   AES encrypts data
            //   RSA encrypts AES key
            byte[] encrypted = encryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            // ==================================================================================
            // STEP 6: EXPECTED DECRYPT FAILURE (CLIENT SIDE)
            // ==================================================================================
            try {
                encryptor.decrypt(encrypted);
                logger.warning("Unexpected: Decryption should not succeed!");
            } catch (Exception ex) {
                logger.info("Expected: Cannot decrypt without PrivateKey.");
            }
            logger.info("========== RSA PUBLIC KEY ADVANCED DEMO V11 COMPLETED ==========");
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Error in RSA PublicKey Advanced Demo V11", ex);
        }
    }
}