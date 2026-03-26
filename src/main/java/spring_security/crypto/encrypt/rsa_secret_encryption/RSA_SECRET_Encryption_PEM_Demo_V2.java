package spring_security.crypto.encrypt.rsa_secret_encryption;

import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_SECRET_Encryption_PEM_Demo_V2
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaSecretEncryptor(String pemData)
 * ------------------------------------------------------------------
 * CORE FUNCTIONALITY
 * ------------------------------------------------------------------
 * ✔ Uses PUBLIC KEY in PEM format
 * ✔ Performs hybrid encryption (RSA + AES)
 * ✔ Supports ENCRYPTION ONLY
 * ------------------------------------------------------------------
 * WHY DECRYPTION IS NOT INCLUDED
 * ------------------------------------------------------------------
 * ❌ This constructor does NOT support private key usage
 * ❌ Hence, decryption is NOT possible here
 * ✔ Real-world interpretation:
 * This acts as a CLIENT-SIDE encryptor
 * ------------------------------------------------------------------
 * INTERNAL HYBRID ENCRYPTION FLOW
 * ------------------------------------------------------------------
 * 1) Generate random AES key
 * 2) Encrypt plaintext using AES
 * 3) Encrypt AES key using RSA PUBLIC KEY
 * 4) Combine → final ciphertext
 * ------------------------------------------------------------------
 * ARCHITECTURE (REAL WORLD)
 * ------------------------------------------------------------------
 * CLIENT: Uses PUBLIC KEY → Encrypts data
 * SERVER: Uses PRIVATE KEY → Decrypts data
 * ------------------------------------------------------------------
 * IMPORTANT REQUIREMENTS
 * ------------------------------------------------------------------
 * ✔ PEM must be PUBLIC KEY format:
 * -----BEGIN PUBLIC KEY-----
 * ❌ NOT supported:
 * -----BEGIN PRIVATE KEY-----
 * -----BEGIN RSA PRIVATE KEY-----
 * ------------------------------------------------------------------
 * USE CASES
 * ------------------------------------------------------------------
 * ✔ Secure API request encryption
 * ✔ Microservice communication
 * ✔ Frontend → Backend secure transmission
 */
public class RSA_SECRET_Encryption_PEM_Demo_V2 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_PEM_Demo_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA SECRET PEM ENCRYPTION DEMO V2 STARTED ==========");

        try {

            //----------------------------------------------------------
            // STEP 1: PROVIDE PUBLIC KEY PEM
            //----------------------------------------------------------
            String publicPem = """
                    -----BEGIN PUBLIC KEY-----
                    MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM9c0Fsf/PWW3bgjLJObwpNb2dbXB04n
                    d3vA6kS1UI2sQIPz+jKsbFV54uHlodOa6ugK5U3PecSTLt/MVrGKirECAwEAAQ==
                    -----END PUBLIC KEY-----
                    """;

            //----------------------------------------------------------
            // STEP 2: INITIALIZE ENCRYPTOR
            //----------------------------------------------------------
            // Internally:
            // • Loads RSA PUBLIC KEY from PEM
            // • Prepares hybrid encryption engine
            RsaSecretEncryptor rsaSecretEncryptor = new RsaSecretEncryptor(publicPem);
            logger.info("Encryptor initialized with PUBLIC KEY.");

            //----------------------------------------------------------
            // STEP 3: PREPARE DATA
            //----------------------------------------------------------
            String data = "RSA Secret PEM Encryption Only Demo V2";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);

            logger.info("Plaintext: " + data);
            logger.info("Plaintext Length: " + plaintext.length + " bytes");

            //----------------------------------------------------------
            // STEP 4: ENCRYPT
            //----------------------------------------------------------
            // Internally:
            // • AES encrypts data
            // • RSA encrypts AES key

            byte[] encrypted = rsaSecretEncryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);

            logger.info("Encrypted Length: " + encrypted.length + " bytes");
            logger.info("Encrypted (Base64): " + base64Cipher);

            //----------------------------------------------------------
            // STEP 5: IMPORTANT NOTE
            //----------------------------------------------------------
            // ❌ Decryption NOT possible here
            //
            // ✔ Requires:
            //      RsaSecretEncryptor(PublicKey, PrivateKey)
            //
            // ✔ Typically done on SERVER side
            logger.info("NOTE: Decryption must be handled separately using PRIVATE KEY.");
            logger.info("========== RSA SECRET PEM ENCRYPTION DEMO V2 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible failures:
            //
            // • Invalid PEM format
            // • Corrupted Base64
            // • Unsupported key structure
            //
            logger.log(Level.SEVERE, "Error in RSA Secret PEM Encryption Demo V2", ex);
        }
    }
}