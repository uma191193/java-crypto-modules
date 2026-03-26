// This code needs to be fixed related to PEM, proper investigation is needed
package spring_security.crypto.encrypt.rsarawencryption;

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
                    -----BEGIN PRIVATE KEY-----
                    MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAz1zQWx/89ZbduCMs
                    k5vCk1vZ1tcHTid3e8DqRLVQjaxAg/P6MqxsVXni4eWh05rq6ArlTc95xJMu38xW
                    sYqK8QIDAQABAkEAq9qeycGQ21MCH2RKDWE/YXdz/BPZt6r9Ga6IpiObOqYkbKx2
                    +8OobQIEk83TeBIjNhBM9DWW3rtkCnqzirSolQIhAP1Gc7YCOjxIqFZ3VAb9/T/j
                    Gj33jjlHzvEihQ/HVbUazAiEA1VdNDO7xjoMnQnXrhIRbkIuAeGHWxirMRHkRkNvM
                    wU0CIQC3NEPoPFcAckU4iigFsMghvYDn8ApX2HFqRSbuuSSMzwIgF8Jo6CQOdht6
                    v7qAbKLFXrruDsP88D6UiHvxCcOvCJ0CIQCjMzdg3NofM8JrIoVNewc19hXtOD87m
                    py4V/mQJu1WDk=
                    -----END PRIVATE KEY-----
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