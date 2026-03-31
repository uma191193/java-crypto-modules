package spring_security.crypto.password4j2;

import com.password4j.BcryptFunction;
import org.springframework.security.crypto.password4j.BcryptPassword4jPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * BCRYPT_PASSWORD4J_ENCODER_DEMO_V2
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: BcryptPassword4jPasswordEncoder(BcryptFunction bcryptFunction)
 * ==========================================================================================
 * CORE CONCEPT: CUSTOM BCRYPT CONFIGURATION (PASSWORD4J)
 * ==========================================================================================
 * Unlike V1 (default configuration), this allows explicit control over:
 * ✔ Cost factor (log rounds)
 * ✔ BCrypt version
 * ==========================================================================================
 * WHY CUSTOM BcryptFunction?
 * ==========================================================================================
 * ✔ Tune performance vs security
 * ✔ Increase hashing cost over time
 * ✔ Match legacy system configurations
 * ==========================================================================================
 * BCRYPT PARAMETERS EXPLAINED
 * ==========================================================================================
 * logRounds (cost factor)
 * → Determines computational cost
 * → Actual iterations = 2^logRounds
 * Example:
 * 10 → 1024 iterations
 * 12 → 4096 iterations
 * 14 → 16384 iterations
 * version
 * → $2a$, $2b$, $2y$
 * → $2b$ is the modern recommended version
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Apply BCrypt hashing using configured cost
 * 3) Embed version, cost, salt, and hash into output
 * matches():
 * 1) Extract cost + salt from encoded string
 * 2) Recompute hash
 * 3) Perform constant-time comparison
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * $2b$12$<salt><hash>
 * Breakdown:
 * $2b$ → version
 * 12   → cost factor
 * salt → 22 chars
 * hash → 31 chars
 * ==========================================================================================
 * SECURITY CHARACTERISTICS
 * ==========================================================================================
 * ✔ Adaptive (configurable cost)
 * ✔ Salt included in hash
 * ✔ Resistant to rainbow table attacks
 * ❌ Not memory-hard (unlike Argon2 / SCrypt)
 * ==========================================================================================
 * PERFORMANCE NOTE
 * ==========================================================================================
 * ✔ Higher cost → stronger security but slower hashing
 * ✔ Recommended range:
 * → 10–12 (general)
 * → 12–14 (high security)
 */
public class BCRYPT_PASSWORD4J_ENCODER_DEMO_V2 {

    private static final Logger logger = Logger.getLogger(BCRYPT_PASSWORD4J_ENCODER_DEMO_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== BCRYPT PASSWORD4J ENCODER DEMO V2 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: CREATE CUSTOM BCRYPT FUNCTION
            // ==================================================================================
            BcryptFunction bcryptFunction = BcryptFunction.getInstance(
                    12   // logRounds (cost factor)
            );

            logger.info("Custom BcryptFunction created with cost factor: 12");

            // ==================================================================================
            // STEP 2: CREATE ENCODER WITH CUSTOM FUNCTION
            // ==================================================================================
            BcryptPassword4jPasswordEncoder bcryptPassword4jPasswordEncoder =
                    new BcryptPassword4jPasswordEncoder(bcryptFunction);

            logger.info("Encoder initialized with custom BCrypt configuration.");

            // ==================================================================================
            // STEP 3: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 4: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = bcryptPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = bcryptPassword4jPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = bcryptPassword4jPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 7: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = bcryptPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * ✔ Different hashes due to random salt
             * ✔ Same cost factor (12) reused internally
             * ✔ Cost + salt embedded in encoded string
             */

            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in BcryptPassword4jPasswordEncoder demo V2", ex);
        }
    }
}