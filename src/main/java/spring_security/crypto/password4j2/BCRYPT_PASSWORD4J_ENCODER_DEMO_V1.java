package spring_security.crypto.password4j2;

import org.springframework.security.crypto.password4j.BcryptPassword4jPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * BCRYPT_PASSWORD4J_ENCODER_DEMO_V1
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: BcryptPassword4jPasswordEncoder()
 * ==========================================================================================
 * CORE CONCEPT: BCRYPT (ADAPTIVE PASSWORD HASHING)
 * ==========================================================================================
 * BCrypt is a widely adopted password hashing algorithm designed to:
 * ✔ Be slow (adaptive) → resists brute-force attacks
 * ✔ Automatically generate salt
 * ✔ Embed cost factor inside the hash
 * ==========================================================================================
 * WHY BCRYPT?
 * ==========================================================================================
 * ✔ Industry standard for password hashing
 * ✔ Built-in salt handling
 * ✔ Adjustable computational cost
 * ✔ Proven and widely supported
 * ==========================================================================================
 * DEFAULT CONSTRUCTOR BEHAVIOR
 * ==========================================================================================
 * BcryptPassword4jPasswordEncoder()
 * ✔ Uses Password4j's default BCrypt configuration
 * ✔ Internally manages:
 * - Salt generation
 * - Cost factor (log rounds)
 * - Secure hash formatting
 * ✔ No manual configuration required
 * ==========================================================================================
 * BCRYPT INTERNAL WORKING
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Apply BCrypt hashing (EksBlowfish-based)
 * 3) Embed:
 * - Algorithm version
 * - Cost factor
 * - Salt
 * - Hash
 * matches():
 * 1) Extract parameters from stored hash
 * 2) Recompute hash using same salt & cost
 * 3) Perform constant-time comparison
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * $2a$10$<22-char-salt><31-char-hash>
 * Example:
 * $2a$10$7EqJtq98hPqEX7fNZaFWoO6b6YyE0zY4xXHzkwmo7aX6ixkmKuuGa
 * Breakdown:
 * $2a$ → version
 * 10   → cost factor (2^10 iterations)
 * salt → 22 chars
 * hash → 31 chars
 * ==========================================================================================
 * SECURITY CHARACTERISTICS
 * ==========================================================================================
 * ✔ Adaptive (cost increases over time)
 * ✔ Salt included in hash
 * ✔ Resistant to rainbow table attacks
 * ❌ Not memory-hard (unlike Argon2/SCrypt)
 * ==========================================================================================
 * COST FACTOR (IMPORTANT)
 * ==========================================================================================
 * Cost = 2^logRounds
 * Example:
 * logRounds = 10 → 1024 iterations
 * logRounds = 12 → 4096 iterations
 * Higher cost → more secure but slower
 * ==========================================================================================
 * WHEN TO USE
 * ==========================================================================================
 * ✔ Default choice for most applications
 * ✔ When Argon2 is not available
 * ✔ When compatibility is important
 * ==========================================================================================
 * WHEN NOT TO USE
 * ==========================================================================================
 * ❌ If memory-hard defense is required → Use Argon2 / SCrypt
 */
public class BCRYPT_PASSWORD4J_ENCODER_DEMO_V1 {

    private static final Logger logger = Logger.getLogger(BCRYPT_PASSWORD4J_ENCODER_DEMO_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== BCRYPT PASSWORD4J ENCODER DEMO V1 STARTED ==========");

        try {

            // ==================================================================================
            // STEP 1: CREATE ENCODER (DEFAULT CONFIGURATION)
            // ==================================================================================
            BcryptPassword4jPasswordEncoder bcryptPassword4jPasswordEncoder = new BcryptPassword4jPasswordEncoder();
            logger.info("BcryptPassword4jPasswordEncoder initialized.");

            // ==================================================================================
            // STEP 2: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 3: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = bcryptPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 4: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = bcryptPassword4jPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = bcryptPassword4jPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 6: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = bcryptPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * ✔ Different hashes due to random salt
             * ✔ Same cost factor reused internally
             * ✔ Salt + cost embedded in encoded string
             */

            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in BcryptPassword4jPasswordEncoder demo", ex);
        }
    }
}