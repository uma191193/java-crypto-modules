package spring_security.crypto.password4j2;

import com.password4j.BalloonHashingFunction;
import org.springframework.security.crypto.password4j.BalloonHashingPassword4jPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * BALLOON_HASHING_PASSWORD4J_ENCODER_DEMO_V2
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: BalloonHashingPassword4jPasswordEncoder(BalloonHashingFunction balloonHashingFunction,
 * int saltLength)
 * ==========================================================================================
 * CORE CONCEPT: CUSTOM BALLOON HASHING CONFIGURATION
 * ==========================================================================================
 * Unlike V1 (default configuration), this allows explicit control over:
 * ✔ Memory cost (space complexity)
 * ✔ Time cost (iterations)
 * ✔ Parallelism (if supported)
 * ✔ Salt length
 * ==========================================================================================
 * WHY CUSTOM CONFIGURATION?
 * ==========================================================================================
 * ✔ Fine-tune security vs performance
 * ✔ Adapt to hardware capabilities
 * ✔ Increase resistance against brute-force / GPU attacks
 * ==========================================================================================
 * BALLOON HASHING PARAMETERS EXPLAINED
 * ==========================================================================================
 * space (memory cost)
 * → Amount of memory used (higher = stronger)
 * time (iterations)
 * → Number of passes over memory (higher = slower & more secure)
 * parallelism
 * → Number of parallel threads (depends on implementation)
 * saltLength
 * → Length of randomly generated salt (bytes)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt (based on saltLength)
 * 2) Apply Balloon hashing function
 * 3) Produce encoded hash
 * matches():
 * 1) Extract parameters from encoded hash
 * 2) Recompute hash
 * 3) Perform secure comparison
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * $balloon$<params>$<salt>$<hash>
 * ==========================================================================================
 * SECURITY CHARACTERISTICS
 * ==========================================================================================
 * ✔ Memory-hard algorithm
 * ✔ Resistant to GPU/ASIC attacks
 * ✔ Configurable cost factors
 */
public class BALLOON_HASHING_PASSWORD4J_ENCODER_DEMO_V2 {

    private static final Logger logger = Logger.getLogger(BALLOON_HASHING_PASSWORD4J_ENCODER_DEMO_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== BALLOON HASHING PASSWORD4J DEMO V2 STARTED ==========");

        try {
            // ==================================================================================
            // STEP 1: CREATE CUSTOM BALLOON HASHING FUNCTION
            // ==================================================================================
            BalloonHashingFunction balloonFunction = BalloonHashingFunction.getInstance(
                    "SHA-256", // Underlying hash algorithm
                    1024,      // space cost (memory usage)
                    3,         // time cost (iterations)
                    1          // parallelism (number of threads)
            );

            logger.info("Custom BalloonHashingFunction created.");

            // ==================================================================================
            // STEP 2: CREATE ENCODER WITH CUSTOM FUNCTION + SALT LENGTH
            // ==================================================================================
            int saltLength = 16; // 16 bytes salt (recommended minimum)

            BalloonHashingPassword4jPasswordEncoder balloonHashingPassword4jPasswordEncoder =
                    new BalloonHashingPassword4jPasswordEncoder(balloonFunction, saltLength);

            logger.info("Encoder initialized with custom configuration.");

            // ==================================================================================
            // STEP 3: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 4: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = balloonHashingPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = balloonHashingPassword4jPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = balloonHashingPassword4jPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 7: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = balloonHashingPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * ✔ Different hashes due to random salt
             * ✔ Same Balloon hashing configuration reused
             * ✔ Salt length impacts entropy (security)
             */

            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in BalloonHashingPassword4jPasswordEncoder demo V2", ex);
        }
    }
}