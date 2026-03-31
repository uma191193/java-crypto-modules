package spring_security.crypto.password;

import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * PBKDF2_PASSWORD_ENCODER_Demo_V2 (Using PBKDF2WithHmacSHA256 Algorithm)
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of:
 * Pbkdf2PasswordEncoder(CharSequence secret, int saltLength, int iterations,
 * SecretKeyFactoryAlgorithm algorithm)
 * (Using PBKDF2WithHmacSHA256 Algorithm)
 * ==========================================================================================
 * CORE CONCEPT: PBKDF2 (PASSWORD-BASED KEY DERIVATION FUNCTION)
 * ==========================================================================================
 * PBKDF2 applies:
 * password + salt + iterations → secure derived hash
 * ✔ Slows down brute-force attacks
 * ✔ Uses HMAC internally
 * ✔ Stronger than SHA-1 variant
 * ==========================================================================================
 * SHA-256 SPECIFIC DETAILS
 * ==========================================================================================
 * Algorithm   : PBKDF2WithHmacSHA256
 * Output Size : 256-bit
 * ✔ Stronger than SHA-1
 * ✔ Recommended for modern applications
 * ==========================================================================================
 * PARAMETER BREAKDOWN
 * ==========================================================================================
 * 1) secret (Pepper)
 * → Additional secret value
 * → Should be stored outside database
 * ------------------------------------------------------------------------------------------
 * 2) saltLength (bytes)
 * → Random salt size
 * → Prevents rainbow table attacks
 * ------------------------------------------------------------------------------------------
 * 3) iterations
 * → Number of hashing rounds
 * → Higher = stronger but slower
 * ------------------------------------------------------------------------------------------
 * 4) algorithm
 * → PBKDF2WithHmacSHA256 (modern recommended)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Apply PBKDF2 with HMAC-SHA256
 * 3) Combine parameters into encoded string
 * matches():
 * 1) Extract salt + iterations
 * 2) Recompute hash
 * 3) Compare securely
 * ==========================================================================================
 * SECURITY NOTES
 * ==========================================================================================
 * ✔ Stronger than SHA-1 variant
 * ✔ Iteration-based protection
 * ✔ Supports pepper (secret)
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * Encoded string contains:
 * iterations + salt + hash
 */
public class PBKDF2_PASSWORD_ENCODER_Demo_V2 {

    private static final Logger logger = Logger.getLogger(PBKDF2_PASSWORD_ENCODER_Demo_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== PBKDF2 PASSWORD ENCODER DEMO V2 STARTED ==========");

        try {
            // ==================================================================================
            // STEP 1: CONFIGURE PARAMETERS
            // ==================================================================================
            CharSequence secret = "ApplicationPepperKey"; // Pepper (keep outside DB)
            int saltLength = 16;                          // 16 bytes salt
            int iterations = 185000;                      // Modern recommended value

            Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm algorithm = Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256;
            logger.info("PBKDF2 parameters configured (SHA-256 variant).");

            // ==================================================================================
            // STEP 2: CREATE ENCODER INSTANCE
            // ==================================================================================
            Pbkdf2PasswordEncoder pbkdf2PasswordEncoder = new Pbkdf2PasswordEncoder(secret, saltLength, iterations, algorithm);

            // Optional: Base64 encoding for readability
            pbkdf2PasswordEncoder.setEncodeHashAsBase64(true);
            logger.info("Pbkdf2PasswordEncoder initialized.");

            // ==================================================================================
            // STEP 3: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 4: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = pbkdf2PasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = pbkdf2PasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = pbkdf2PasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 7: COMPLETE
            // ==================================================================================
            logger.info("========== PBKDF2 DEMO V2 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in PBKDF2 Password Encoder demo V2", ex);
        }
    }
}