package spring_security.crypto.password4j2;

import org.springframework.security.crypto.password4j.Argon2Password4jPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * ARGON2_PASSWORD4J_PASSWORD_ENCODER_DEMO_V1
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: Argon2Password4jPasswordEncoder()
 * ==========================================================================================
 * CORE CONCEPT: ARGON2 (MODERN PASSWORD HASHING)
 * ==========================================================================================
 * Argon2 is the winner of the Password Hashing Competition (PHC)
 * password + salt + memory + iterations + parallelism → secure hash
 * ✔ Memory-hard
 * ✔ Resistant to GPU/ASIC attacks
 * ✔ Adaptive (configurable cost)
 * ==========================================================================================
 * PASSWORD4J INTEGRATION
 * ==========================================================================================
 * This implementation uses Password4j internally:
 * ✔ Provides advanced Argon2 configuration
 * ✔ Cleaner API abstraction
 * ✔ Better tuning capabilities
 * ==========================================================================================
 * DEFAULT CONFIGURATION (IMPORTANT)
 * ==========================================================================================
 * When using: Argon2Password4jPasswordEncoder()
 * It applies internally tuned defaults:
 * ✔ Salt → Automatically generated
 * ✔ Memory cost → Secure default
 * ✔ Iterations → Balanced value
 * ✔ Parallelism → System-optimized
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Apply Argon2 (memory + iterations + parallelism)
 * 3) Produce encoded hash string
 * matches():
 * 1) Extract parameters from encoded string
 * 2) Recompute Argon2 hash
 * 3) Secure comparison
 * ==========================================================================================
 * SECURITY ADVANTAGES
 * ==========================================================================================
 * ✔ Memory hardness (prevents GPU attacks)
 * ✔ Adaptive cost
 * ✔ Automatic salting
 * ✔ Modern standard (recommended)
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * Encoded string contains:
 * algorithm + parameters + salt + hash
 * Example:
 * $argon2id$v=19$m=...$salt$hash
 * ==========================================================================================
 * COMPARISON NOTE
 * ==========================================================================================
 * ✔ Stronger than:
 * • BCrypt
 * • PBKDF2
 * ✔ Recommended for new systems
 */
public class ARGON2_PASSWORD4J_PASSWORD_ENCODER_DEMO_V1 {

    private static final Logger logger = Logger.getLogger(ARGON2_PASSWORD4J_PASSWORD_ENCODER_DEMO_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== ARGON2 PASSWORD4J ENCODER DEMO V2 STARTED ==========");
        try {

            // ==================================================================================
            // STEP 1: CREATE ENCODER INSTANCE (DEFAULT CONFIG)
            // ==================================================================================
            Argon2Password4jPasswordEncoder argon2Password4jPasswordEncoder = new Argon2Password4jPasswordEncoder();
            logger.info("Argon2Password4jPasswordEncoder initialized with defaults.");

            // ==================================================================================
            // STEP 2: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 3: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = argon2Password4jPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 4: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = argon2Password4jPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = argon2Password4jPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 6: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = argon2Password4jPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));
            /**
             * Insight:
             * ✔ Different hashes due to random salt
             * ✔ Argon2 ensures strong uniqueness
             */
            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== ARGON2 PASSWORD4J ENCODER DEMO V2 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in Argon2Password4jPasswordEncoder demo V2", ex);
        }
    }
}