package spring_security.crypto.password4j2;

import org.springframework.security.crypto.password4j.BalloonHashingPassword4jPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * BALLOON_HASHING_PASSWORD4J_ENCODER_DEMO_V1
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: BalloonHashingPassword4jPasswordEncoder()
 * ==========================================================================================
 * CORE CONCEPT: BALLOON HASHING (MEMORY-HARD PASSWORD HASHING)
 * ==========================================================================================
 * Balloon Hashing is a modern password hashing algorithm designed to:
 * ✔ Be memory-hard (resistant to GPU/ASIC attacks)
 * ✔ Prevent time-memory trade-off attacks
 * ✔ Provide strong protection against brute-force attacks
 * It is conceptually similar to:
 * → Argon2
 * → SCrypt
 * ==========================================================================================
 * WHY USE BALLOON HASHING?
 * ==========================================================================================
 * ✔ Strong defense against parallel attacks
 * ✔ Tunable memory and time cost
 * ✔ Suitable for modern secure systems
 * HOWEVER:
 * ✔ Less widely adopted compared to Argon2
 * ✔ Limited ecosystem support
 * ==========================================================================================
 * DEFAULT CONSTRUCTOR BEHAVIOR
 * ==========================================================================================
 * BalloonHashingPassword4jPasswordEncoder()
 * ✔ Uses Password4j's default Balloon hashing configuration
 * ✔ Internally manages:
 * - Salt generation
 * - Hashing parameters
 * - Secure encoding format
 * ✔ No manual configuration required
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Apply Balloon hashing function
 * 3) Produce encoded hash string
 * matches():
 * 1) Extract parameters from encoded hash
 * 2) Recompute hash
 * 3) Perform constant-time comparison
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * $balloon$...$salt$hash
 * (Exact format may vary depending on Password4j version)
 * ==========================================================================================
 * SECURITY CHARACTERISTICS
 * ==========================================================================================
 * ✔ Memory-hard
 * ✔ Slows down attackers significantly
 * ✔ Resistant to GPU acceleration
 * ==========================================================================================
 * WHEN TO USE
 * ==========================================================================================
 * ✔ When Argon2 is unavailable
 * ✔ When experimenting with alternative memory-hard algorithms
 * ==========================================================================================
 * WHEN NOT TO USE
 * ==========================================================================================
 * ❌ If industry-standard compliance is required → Use Argon2 / BCrypt
 * ❌ If library support is limited in your ecosystem
 */
public class BALLOON_HASHING_PASSWORD4J_ENCODER_DEMO_V1 {

    private static final Logger logger = Logger.getLogger(BALLOON_HASHING_PASSWORD4J_ENCODER_DEMO_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== BALLOON HASHING PASSWORD4J DEMO V1 STARTED ==========");
        try {

            // ==================================================================================
            // STEP 1: CREATE ENCODER (DEFAULT CONFIGURATION)
            // ==================================================================================
            BalloonHashingPassword4jPasswordEncoder balloonHashingPassword4jPasswordEncoder =
                    new BalloonHashingPassword4jPasswordEncoder();

            logger.info("BalloonHashingPassword4jPasswordEncoder initialized.");

            // ==================================================================================
            // STEP 2: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 3: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = balloonHashingPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 4: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = balloonHashingPassword4jPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = balloonHashingPassword4jPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 6: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = balloonHashingPassword4jPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * ✔ Different hashes due to random salt
             * ✔ Same internal algorithm configuration
             * ✔ Secure verification works via embedded parameters
             */

            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in BalloonHashingPassword4jPasswordEncoder demo", ex);
        }
    }
}