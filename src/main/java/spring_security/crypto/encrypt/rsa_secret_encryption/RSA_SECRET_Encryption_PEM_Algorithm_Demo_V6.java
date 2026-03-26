package spring_security.crypto.encrypt.rsa_secret_encryption;

import org.springframework.security.crypto.encrypt.RsaAlgorithm;
import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_SECRET_Encryption_PEM_Algorithm_Demo_V6
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaSecretEncryptor(String pemData, RsaAlgorithm algorithm)
 * ------------------------------------------------------------------
 * CORE IDEA
 * ------------------------------------------------------------------
 * ✔ Load RSA key from PEM
 * ✔ Apply specific RSA algorithm (padding)
 * ✔ Perform hybrid encryption (RSA + AES)
 * ------------------------------------------------------------------
 * SUPPORTED PEM FORMAT
 * ------------------------------------------------------------------
 * ✔ PUBLIC KEY ONLY:
 * -----BEGIN PUBLIC KEY-----
 * ❌ PRIVATE KEY NOT SUPPORTED in this constructor
 * ------------------------------------------------------------------
 * KEY BEHAVIOR
 * ------------------------------------------------------------------
 * ✔ PUBLIC KEY → Encryption only
 * ❌ Decryption NOT possible (no private key)
 * ------------------------------------------------------------------
 * RSA ALGORITHMS
 * ------------------------------------------------------------------
 * ✔ DEFAULT   → PKCS#1 v1.5 (legacy)
 * ✔ OAEP      → SHA-1 based OAEP
 * ✔ OAEP_256  → SHA-256 based OAEP (recommended)
 * ------------------------------------------------------------------
 * INTERNAL FLOW (HYBRID ENCRYPTION)
 * ------------------------------------------------------------------
 * 1) Generate AES key
 * 2) Encrypt data using AES
 * 3) Encrypt AES key using RSA (selected algorithm)
 * 4) Combine → ciphertext
 * ------------------------------------------------------------------
 * USE CASE
 * ------------------------------------------------------------------
 * ✔ Client-side encryption (frontend → backend)
 * ✔ Secure data transmission
 */
public class RSA_SECRET_Encryption_PEM_Algorithm_Demo_V6 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_PEM_Algorithm_Demo_V6.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA SECRET PEM ALGORITHM DEMO V6 STARTED ==========");
        try {
            //----------------------------------------------------------
            // STEP 1: PUBLIC KEY PEM (REQUIRED)
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
            // Recommended: OAEP_256
            RsaAlgorithm algorithm = RsaAlgorithm.OAEP;
            logger.info("Selected Algorithm: " + algorithm);
            //----------------------------------------------------------
            // STEP 3: INITIALIZE ENCRYPTOR
            //----------------------------------------------------------
            // Internally:
            // • Parses PUBLIC KEY from PEM
            // • Prepares hybrid encryption engine
            RsaSecretEncryptor rsaSecretEncryptor = new RsaSecretEncryptor(pemData, algorithm);
            logger.info("Encryptor initialized using PEM + Algorithm.");

            //----------------------------------------------------------
            // STEP 4: PREPARE DATA
            //----------------------------------------------------------
            String data = "RSA Secret PEM Algorithm Demo V6";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);
            //----------------------------------------------------------
            // STEP 5: ENCRYPT
            //----------------------------------------------------------
            byte[] encrypted = rsaSecretEncryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);
            //----------------------------------------------------------
            // ❌ NO DECRYPT STEP
            //----------------------------------------------------------
            // Reason: This constructor does NOT accept PrivateKey
            logger.info("========== ENCRYPTION COMPLETED (NO DECRYPT) ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible issues:
            //
            // • Invalid PEM format
            // • Unsupported algorithm
            // • Corrupted Base64
            //
            logger.log(Level.SEVERE, "Error in RSA Secret PEM Algorithm Demo V6", ex);
        }
    }
}