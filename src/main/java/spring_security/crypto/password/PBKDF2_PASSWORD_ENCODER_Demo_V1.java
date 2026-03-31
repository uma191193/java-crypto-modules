package spring_security.crypto.password;

import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * PBKDF2_PASSWORD_ENCODER_Demo_V1 (Using PBKDF2WithHmacSHA1 Algorithm)
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of:
 * Pbkdf2PasswordEncoder(
 * CharSequence secret,
 * int saltLength,
 * int iterations,
 * Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm algorithm)
 * ==========================================================================================
 * CORE CONCEPT: PBKDF2 (KEY DERIVATION FUNCTION)
 * ==========================================================================================
 * PBKDF2 = Password-Based Key Derivation Function
 * password + salt + iterations → derived secure hash
 * ✔ Slows down brute-force attacks
 * ✔ Uses HMAC internally (HmacSHA1 / HmacSHA256 / HmacSHA512)
 * ==========================================================================================
 * PARAMETER BREAKDOWN
 * ==========================================================================================
 * 1) secret (Pepper)
 * → Additional secret value (application-level)
 * → Stored separately from DB (VERY IMPORTANT)
 * ------------------------------------------------------------------------------------------
 * 2) saltLength (bytes)
 * → Random salt size
 * → Prevents rainbow table attacks
 * ------------------------------------------------------------------------------------------
 * 3) iterations
 * → Number of hashing rounds
 * → Higher = more secure but slower
 * ------------------------------------------------------------------------------------------
 * 4) SecretKeyFactoryAlgorithm
 * → Underlying HMAC algorithm
 * Available:
 * • PBKDF2WithHmacSHA1   (older)
 * • PBKDF2WithHmacSHA256 (recommended)
 * • PBKDF2WithHmacSHA512 (strongest)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Apply PBKDF2 with iterations
 * 3) Produce encoded string containing parameters
 * matches():
 * 1) Extract salt + iterations
 * 2) Recompute hash
 * 3) Compare securely
 * ==========================================================================================
 * SECURITY NOTES
 * ==========================================================================================
 * ✔ Slower than SHA → GOOD for password storage
 * ✔ Supports pepper (secret)
 * ✔ Configurable strength
 * ==========================================================================================
 * IMPORTANT: ENCODE FORMAT
 * ==========================================================================================
 * Encoded string contains:
 * iterations + salt + hash
 */
public class PBKDF2_PASSWORD_ENCODER_Demo_V1 {

    private static final Logger logger = Logger.getLogger(PBKDF2_PASSWORD_ENCODER_Demo_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== PBKDF2 PASSWORD ENCODER DEMO STARTED ==========");
        try {

            // ==================================================================================
            // STEP 1: CONFIGURE PARAMETERS
            // ==================================================================================

            CharSequence secret = "ApplicationPepperKey"; // PEPPER (store securely outside DB)
            int saltLength = 16;                          // 16 bytes salt
            int iterations = 185000;                      // Recommended modern value

            Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm algorithm =
                    Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1;

            logger.info("PBKDF2 parameters configured.");

            // ==================================================================================
            // STEP 2: CREATE ENCODER INSTANCE
            // ==================================================================================
            Pbkdf2PasswordEncoder pbkdf2PasswordEncoder = new Pbkdf2PasswordEncoder(secret, saltLength, iterations, algorithm);

            // Optional: Encode output as Base64 instead of hex
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
            logger.info("========== PBKDF2 DEMO V1 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in PBKDF2 Password Encoder demo V1", ex);
        }
    }
}