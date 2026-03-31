package spring_security.crypto.password4j2;

import com.password4j.ScryptFunction;
import org.springframework.security.crypto.password4j.ScryptPassword4jPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * SCRYPT_PASSWORD4J_ENCODER_DEMO_V2
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: ScryptPassword4jPasswordEncoder(ScryptFunction scryptFunction)
 * ==========================================================================================
 * CORE CONCEPT: CUSTOM SCRYPT CONFIGURATION (PASSWORD4J)
 * ==========================================================================================
 * Unlike V1 (default configuration), this allows FULL control over:
 * ✔ N (CPU/memory cost)
 * ✔ r (block size)
 * ✔ p (parallelization)
 * ==========================================================================================
 * WHY CUSTOM ScryptFunction?
 * ==========================================================================================
 * ✔ Fine-tune memory vs performance
 * ✔ Increase resistance to brute-force attacks
 * ✔ Adapt to hardware capabilities
 * ==========================================================================================
 * SCRYPT PARAMETERS EXPLAINED
 * ==========================================================================================
 * N (cost parameter)
 * → Must be a power of 2 (e.g., 16384)
 * → Controls CPU + memory usage
 * r (block size)
 * → Affects memory consumption
 * p (parallelization)
 * → Number of independent computations
 * ==========================================================================================
 * RECOMMENDED SETTINGS
 * ==========================================================================================
 * ✔ N = 16384 (2^14) or higher
 * ✔ r = 8
 * ✔ p = 1 (or higher based on CPU)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Apply SCrypt with configured parameters
 * 3) Produce encoded hash string
 * matches():
 * 1) Extract parameters + salt from encoded string
 * 2) Recompute hash
 * 3) Perform constant-time comparison
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * $scrypt$N=<value>,r=<value>,p=<value>$<salt>$<hash>
 * ==========================================================================================
 * SECURITY CHARACTERISTICS
 * ==========================================================================================
 * ✔ Memory-hard (resistant to GPU/ASIC attacks)
 * ✔ Configurable cost parameters
 * ✔ Salt included in hash
 */
public class SCRYPT_PASSWORD4J_ENCODER_DEMO_V2 {

    private static final Logger logger = Logger.getLogger(SCRYPT_PASSWORD4J_ENCODER_DEMO_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== SCRYPT PASSWORD4J ENCODER DEMO V2 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: CREATE CUSTOM SCRYPT FUNCTION
            // ==================================================================================
            ScryptFunction scryptFunction = ScryptFunction.getInstance(
                    16384, // N (CPU/memory cost, must be power of 2)
                    8,     // r (block size)
                    1      // p (parallelization)
            );
            logger.info("Custom ScryptFunction created (N=16384, r=8, p=1).");

            // ==================================================================================
            // STEP 2: CREATE ENCODER WITH CUSTOM FUNCTION
            // ==================================================================================
            ScryptPassword4jPasswordEncoder scryptPassword4jPasswordEncoder =
                    new ScryptPassword4jPasswordEncoder(scryptFunction);

            logger.info("Encoder initialized with custom SCrypt configuration.");

            // ==================================================================================
            // STEP 3: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 4: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = scryptPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = scryptPassword4jPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = scryptPassword4jPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 7: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = scryptPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * ✔ Different hashes due to random salt
             * ✔ Same N, r, p parameters reused internally
             * ✔ Parameters embedded in encoded string
             */

            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in ScryptPassword4jPasswordEncoder demo V2", ex);
        }
    }
}