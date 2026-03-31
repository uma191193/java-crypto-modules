package spring_security.crypto.password4j2;

import org.springframework.security.crypto.password4j.ScryptPassword4jPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * SCRYPT_PASSWORD4J_ENCODER_DEMO_V1
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: ScryptPassword4jPasswordEncoder()
 * ==========================================================================================
 * CORE CONCEPT: SCRYPT (MEMORY-HARD PASSWORD HASHING)
 * ==========================================================================================
 * SCrypt is a modern password hashing algorithm designed to:
 * ✔ Be memory-hard (high RAM usage)
 * ✔ Resist GPU / ASIC attacks
 * ✔ Prevent time-memory trade-off attacks
 * It improves over PBKDF2 by adding:
 * → Significant memory consumption during hashing
 * ==========================================================================================
 * WHY USE SCRYPT?
 * ==========================================================================================
 * ✔ Strong resistance to parallel brute-force attacks
 * ✔ Memory-hard design slows down attackers significantly
 * ✔ Widely accepted alternative to Argon2
 * ==========================================================================================
 * DEFAULT CONSTRUCTOR BEHAVIOR
 * ==========================================================================================
 * ScryptPassword4jPasswordEncoder()
 * ✔ Uses Password4j’s default SCrypt configuration
 * ✔ Internally manages:
 * - Salt generation
 * - Cost parameters (N, r, p)
 * - Hash formatting
 * ✔ No manual configuration required
 * ==========================================================================================
 * SCRYPT PARAMETERS (INTERNAL)
 * ==========================================================================================
 * N (CPU/memory cost)
 * → Must be power of 2 (e.g., 16384)
 * r (block size)
 * → Affects memory usage
 * p (parallelization)
 * → Number of parallel threads
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Apply SCrypt hashing using parameters (N, r, p)
 * 3) Produce encoded hash string
 * matches():
 * 1) Extract parameters + salt from encoded string
 * 2) Recompute hash
 * 3) Perform constant-time comparison
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * $scrypt$N=<value>,r=<value>,p=<value>$<salt>$<hash>
 * (Exact format may vary depending on Password4j version)
 * ==========================================================================================
 * SECURITY CHARACTERISTICS
 * ==========================================================================================
 * ✔ Memory-hard (strong against GPU attacks)
 * ✔ Adaptive via parameter tuning
 * ✔ Salt included in hash
 * ==========================================================================================
 * WHEN TO USE
 * ==========================================================================================
 * ✔ When Argon2 is unavailable
 * ✔ When strong memory-hard protection is needed
 * ==========================================================================================
 * WHEN NOT TO USE
 * ==========================================================================================
 * ❌ If system memory constraints are tight
 * ❌ If Argon2 is available (preferred modern choice)
 */
public class SCRYPT_PASSWORD4J_ENCODER_DEMO_V1 {

    private static final Logger logger = Logger.getLogger(SCRYPT_PASSWORD4J_ENCODER_DEMO_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== SCRYPT PASSWORD4J ENCODER DEMO V1 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: CREATE ENCODER (DEFAULT CONFIGURATION)
            // ==================================================================================
            ScryptPassword4jPasswordEncoder scryptPassword4jPasswordEncoder = new ScryptPassword4jPasswordEncoder();
            logger.info("ScryptPassword4jPasswordEncoder initialized.");

            // ==================================================================================
            // STEP 2: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 3: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = scryptPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 4: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = scryptPassword4jPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = scryptPassword4jPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 6: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = scryptPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * ✔ Different hashes due to random salt
             * ✔ Same SCrypt parameters reused internally
             * ✔ Parameters + salt embedded in encoded string
             */

            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in ScryptPassword4jPasswordEncoder demo V1", ex);
        }
    }
}