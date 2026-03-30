// This code needs to be fixed related to PEM, proper investigation is needed
package spring_security.crypto.encrypt.rsa_raw_encryption;

import org.springframework.security.crypto.encrypt.RsaRawEncryptor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_RAW_Encryption_PEM_Demo_V5
 * ------------------------------------------------------------------
 * ✔ Uses VALID PKCS#8 PEM format (BEGIN PRIVATE KEY)
 * ✔ Compatible with RsaRawEncryptor
 * ------------------------------------------------------------------
 * IMPORTANT FIX
 * ------------------------------------------------------------------
 * ❌ OLD (WRONG):
 * -----BEGIN RSA PRIVATE KEY-----  (PKCS#1 → NOT supported)
 * ✔ NEW (CORRECT):
 * -----BEGIN PRIVATE KEY-----      (PKCS#8 → REQUIRED)
 * ------------------------------------------------------------------
 * HOW TO GENERATE VALID PEM
 * ------------------------------------------------------------------
 * Use OpenSSL:
 * openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
 * ------------------------------------------------------------------
 */
public class RSA_RAW_Encryption_PEM_Demo_V5 {

    private static final Logger logger = Logger.getLogger(RSA_RAW_Encryption_PEM_Demo_V5.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA RAW PEM DEMO V5 STARTED ==========");

        try {

            //----------------------------------------------------------
            // STEP 1: VALID PKCS#8 PEM (FIXED)
            //----------------------------------------------------------
            String pemData = """
                                   -----BEGIN RSA PRIVATE KEY-----
                                   MIICXAIBAAKBgQD6vqn19W/VB215DBADRakfPmCtFBf8/+YyhGqixWIwDiEl/L6L
                                   w5HKZCUPVgrC0ADhJfvAbn4fte5MWBCTkqgepKL3BySMA0LMaBF12pbHlPSUbmQG
                                   BJmTX4NNXuUel6TbPYJAU2Nh5Nan0Mb7Bmb8QpFvS0Hw7qZRW8y2eIttfwIDAQAB
                                   AoGBAJVf9FxkRKUB8cOE3h006JWGUY2KROghgn9hxy0ErYO3RyQcN1+HuFh75GAI
                                   gAyiYYO/XwS6TkSR2057wBRJ8ABzcL3+v5g+16Vbh0BjXVE+cv1WGdNGujyzl6ji
                                   jlyF4cb6tXDyqWTLkMAtV20NfO/CGsfii6YEkZb2P90usthRAkEA/oG7a9EvQ7eR
                                   gSEqppzW7KCwidPjnZTr/ROIZQU33nwkIJ0ElTjMNYKP8DerSuixR9skw2ZY8Q8I
                                   1PTBnocHwwJBAPw3SAQYwxZwQMu1trVPMNOGIbSY4rQlMZGXrCZSu/TnozczFLA8
                                   qNM84g5veyJOzHKmYkIsMG1gwg5VNniG45UCQF6SlLOW0upl70K9sVyiUVcyywcc
                    Xqty6FJtjLSFQOKC3OXlkwtkRLXpo1UPSq6WUzIxY7LceFZzUMPZg41F/gMCQHNr
                                   POqbBlPzZMOUUZthNP/nhu8lc8Fqr+dnmGElRVxK0JdHKfWInN2mI/DlNV064Dar
                                   S5XqsPKs78EtX7MCT40CQFQZiry8m7ROubOU4+HDG9o1w9zcKXCkmbD9hBCGvTAj
                                   BQNuGE0DtC6FEWTs8bXybLM5yBRq1XiKLdmi5N+3n4g=
                                   -----END RSA PRIVATE KEY-----
                    """;

            Objects.requireNonNull(pemData, "PEM data must not be null");

            //----------------------------------------------------------
            // STEP 2: INITIALIZE ENCRYPTOR
            //----------------------------------------------------------
            RsaRawEncryptor rsaRawEncryptor = new RsaRawEncryptor(pemData);
            logger.info("Encryptor initialized using PKCS#8 PEM.");

            //----------------------------------------------------------
            // STEP 3: PREPARE PLAINTEXT
            //----------------------------------------------------------
            String data = "RSA PEM Constructor Demo V5";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);

            logger.info("Plaintext: " + data);

            //----------------------------------------------------------
            // STEP 4: ENCRYPT
            //----------------------------------------------------------
            byte[] encrypted = rsaRawEncryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);

            logger.info("Encrypted (Base64): " + base64Cipher);

            //----------------------------------------------------------
            // STEP 5: DECRYPT
            //----------------------------------------------------------
            byte[] decrypted = rsaRawEncryptor.decrypt(encrypted);
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
            logger.info("========== RSA RAW PEM DEMO V5 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            logger.log(Level.SEVERE, "Error during RSA PEM demo", ex);
        }
    }
}