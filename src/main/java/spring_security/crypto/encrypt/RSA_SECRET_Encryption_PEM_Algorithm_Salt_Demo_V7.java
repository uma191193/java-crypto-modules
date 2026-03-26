package spring_security.crypto.encrypt;

import org.springframework.security.crypto.encrypt.RsaAlgorithm;
import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_SECRET_Encryption_PEM_Algorithm_Salt_Demo_V7
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaSecretEncryptor(String pemData,RsaAlgorithm algorithm,String salt)
 * ------------------------------------------------------------------
 * WHAT IS NEW IN V7?
 * ------------------------------------------------------------------
 * ✔ Adds SALT to PEM + Algorithm constructor
 * ✔ Enhances randomness in AES key handling
 * ------------------------------------------------------------------
 * SUPPORTED PEM FORMAT
 * ------------------------------------------------------------------
 * ✔ PUBLIC KEY ONLY:
 * -----BEGIN PUBLIC KEY-----
 * ❌ PRIVATE KEY NOT supported in this constructor
 * ------------------------------------------------------------------
 * KEY BEHAVIOR
 * ------------------------------------------------------------------
 * ✔ PUBLIC KEY → Encryption only
 * ❌ Decryption NOT possible (no private key)
 * ------------------------------------------------------------------
 * INTERNAL FLOW (HYBRID ENCRYPTION)
 * ------------------------------------------------------------------
 * 1) Apply salt influence (key strengthening context)
 * 2) Generate AES key
 * 3) Encrypt plaintext using AES
 * 4) Encrypt AES key using RSA (selected algorithm)
 * 5) Combine → ciphertext
 * ------------------------------------------------------------------
 * SALT ROLE
 * ------------------------------------------------------------------
 * • Adds extra entropy / variation
 * • Helps avoid deterministic patterns
 * • Should be:
 * ✔ Random (in production)
 * ✔ Consistent if decryption is expected elsewhere
 * ------------------------------------------------------------------
 * RSA ALGORITHM OPTIONS
 * ------------------------------------------------------------------
 * ✔ DEFAULT
 * ✔ OAEP
 * ✔ OAEP_256 (recommended)
 * <p>
 * ------------------------------------------------------------------
 * USE CASE
 * ------------------------------------------------------------------
 * ✔ Client-side encryption with enhanced randomness
 * ✔ Secure payload transmission to backend
 */
public class RSA_SECRET_Encryption_PEM_Algorithm_Salt_Demo_V7 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_PEM_Algorithm_Salt_Demo_V7.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA SECRET PEM + ALGO + SALT DEMO V7 STARTED ==========");
        try {

            //----------------------------------------------------------
            // STEP 1: PUBLIC KEY PEM
            //----------------------------------------------------------
            String pemData = """
                    -----BEGIN PUBLIC KEY-----
                    MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM9c0Fsf/PWW3bgjLJObwpNb2dbXB04n
                    d3vA6kS1UI2sQIPz+jKsbFV54uHlodOa6ugK5U3PecSTLt/MVrGKirECAwEAAQ==
                    -----END PUBLIC KEY-----
                    """;

            Objects.requireNonNull(pemData, "PEM data must not be null");

            //----------------------------------------------------------
            // STEP 2: SELECT RSA ALGORITHM
            //----------------------------------------------------------
            RsaAlgorithm algorithm = RsaAlgorithm.OAEP;

            //----------------------------------------------------------
            // STEP 3: DEFINE SALT
            //----------------------------------------------------------
            // In real systems → use secure random generator
            String salt = "s@ltValue123456";

            logger.info("Algorithm: " + algorithm);
            logger.info("Salt: " + salt);

            //----------------------------------------------------------
            // STEP 4: INITIALIZE ENCRYPTOR
            //----------------------------------------------------------
            // Internally:
            // • Parses PUBLIC KEY
            // • Applies algorithm (OAEP_256)
            // • Uses salt in AES key derivation context

            RsaSecretEncryptor encryptor = new RsaSecretEncryptor(pemData, algorithm, salt);
            logger.info("Encryptor initialized (PEM + Algorithm + Salt).");

            //----------------------------------------------------------
            // STEP 5: PREPARE DATA
            //----------------------------------------------------------
            String data = "RSA Secret PEM V7 (Algorithm + Salt)";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);

            logger.info("Plaintext: " + data);

            //----------------------------------------------------------
            // STEP 6: ENCRYPT
            //----------------------------------------------------------
            byte[] encrypted = encryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            //----------------------------------------------------------
            // ❌ NO DECRYPT STEP
            //----------------------------------------------------------
            // Reason:
            // • No PrivateKey provided
            // • This is encryption-only constructor
            logger.info("========== ENCRYPTION COMPLETED (V7) ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible issues:
            //
            // • Invalid PEM format
            // • Unsupported RSA algorithm
            // • Incorrect salt usage
            //
            logger.log(Level.SEVERE, "Error in RSA Secret PEM Algorithm Salt Demo V7", ex);
        }
    }
}