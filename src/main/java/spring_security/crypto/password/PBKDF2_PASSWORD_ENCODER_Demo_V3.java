package spring_security.crypto.password;

import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * PBKDF2_PASSWORD_ENCODER_Demo_V3 (Using PBKDF2WithHmacSHA512 Algorithm)
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of:
 * Pbkdf2PasswordEncoder(CharSequence secret, int saltLength, int iterations,
 * SecretKeyFactoryAlgorithm algorithm)
 * ==========================================================================================
 * CORE CONCEPT: PBKDF2 (PASSWORD-BASED KEY DERIVATION FUNCTION)
 * ==========================================================================================
 * password + salt + iterations → derived secure hash
 * ✔ Strongest among SHA variants (SHA1 < SHA256 < SHA512)
 * ✔ Higher output size → better resistance to collisions
 * ==========================================================================================
 * SHA-512 SPECIFIC DETAILS
 * ==========================================================================================
 * Algorithm   : PBKDF2WithHmacSHA512
 * Output Size : 512-bit
 * ✔ Highest security among PBKDF2 variants
 * ✔ Slightly slower than SHA-256 (expected & acceptable)
 * ==========================================================================================
 * PARAMETER BREAKDOWN
 * ==========================================================================================
 * 1) secret (Pepper)
 * → Extra application-level secret
 * → MUST be stored securely outside DB
 * ------------------------------------------------------------------------------------------
 * 2) saltLength
 * → Random salt (16 bytes recommended)
 * ------------------------------------------------------------------------------------------
 * 3) iterations
 * → Cost factor (higher = stronger)
 * ------------------------------------------------------------------------------------------
 * 4) algorithm
 * → PBKDF2WithHmacSHA512 (strongest variant)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Apply PBKDF2 with HMAC-SHA512
 * 3) Store encoded result (salt + hash + iterations)
 * matches():
 * 1) Extract parameters
 * 2) Recompute hash
 * 3) Secure compare
 * ==========================================================================================
 * SECURITY NOTES
 * ==========================================================================================
 * ✔ Strongest PBKDF2 variant
 * ✔ Slower → better brute-force resistance
 * ✔ Supports pepper
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * iterations + salt + hash
 */
public class PBKDF2_PASSWORD_ENCODER_Demo_V3 {

    private static final Logger logger = Logger.getLogger(PBKDF2_PASSWORD_ENCODER_Demo_V3.class.getName());

    public static void main(String[] args) {

        logger.info("========== PBKDF2 PASSWORD ENCODER DEMO V3 STARTED ==========");

        try {
            // ==================================================================================
            // STEP 1: CONFIGURATION
            // ==================================================================================
            CharSequence secret = "ApplicationPepperKey";
            int saltLength = 16;
            int iterations = 185000;

            Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm algorithm = Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA512;
            logger.info("PBKDF2 parameters configured (SHA-512 variant).");

            // ==================================================================================
            // STEP 2: CREATE ENCODER
            // ==================================================================================
            Pbkdf2PasswordEncoder pbkdf2PasswordEncoder = new Pbkdf2PasswordEncoder(secret, saltLength, iterations, algorithm);
            pbkdf2PasswordEncoder.setEncodeHashAsBase64(true);
            logger.info("Pbkdf2PasswordEncoder initialized.");

            // ==================================================================================
            // STEP 3: RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";

            // ==================================================================================
            // STEP 4: ENCODE
            // ==================================================================================
            String encodedPassword = pbkdf2PasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 5: MATCH (CORRECT)
            // ==================================================================================
            boolean isMatch = pbkdf2PasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: MATCH (WRONG)
            // ==================================================================================
            boolean isWrongMatch = pbkdf2PasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== PBKDF2 DEMO V3 COMPLETED ==========");
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Error in PBKDF2 Password Encoder demo V3", ex);
        }
    }
}