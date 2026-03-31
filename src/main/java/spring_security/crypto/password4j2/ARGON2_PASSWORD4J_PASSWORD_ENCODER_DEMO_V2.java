package spring_security.crypto.password4j2;

import com.password4j.Argon2Function;
import com.password4j.types.Argon2;
import org.springframework.security.crypto.password4j.Argon2Password4jPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * ARGON2_PASSWORD4J_PASSWORD_ENCODER_DEMO_V2
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of:
 * Argon2Password4jPasswordEncoder(Argon2Function argon2Function)
 * ==========================================================================================
 * CORE CONCEPT: FULL ARGON2 CUSTOM CONFIGURATION (PASSWORD4J)
 * ==========================================================================================
 * This approach provides complete control over:
 * ✔ Memory cost
 * ✔ Iterations (time cost)
 * ✔ Parallelism (threads)
 * ✔ Output length (hash size)
 * ✔ Variant (Argon2i / Argon2d / Argon2id)
 * ✔ Version (Argon2 v1.0 vs v1.3)
 * ==========================================================================================
 * WHY USE CUSTOM Argon2Function?
 * ==========================================================================================
 * Default constructor → predefined safe configuration
 * Custom Argon2Function → fine-tuned for:
 * ✔ High-security systems
 * ✔ Hardware-aware tuning
 * ✔ Performance vs security balancing
 * ✔ Compliance requirements (e.g., OWASP, NIST)
 * ==========================================================================================
 * ARGON2 PARAMETERS EXPLAINED
 * ==========================================================================================
 * memory (KB)
 * → RAM usage (higher = stronger against GPU attacks)
 * iterations (time cost)
 * → Number of passes (higher = slower, more secure)
 * parallelism
 * → Number of threads (depends on CPU cores)
 * outputLength
 * → Length of generated hash (e.g., 32 bytes)
 * type (Argon2 variant)
 * → Argon2.i  → side-channel resistant
 * → Argon2.d  → GPU resistant
 * → Argon2.id → hybrid (RECOMMENDED)
 * version
 * → 0x10 (16) → Argon2 v1.0
 * → 0x13 (19) → Argon2 v1.3 (RECOMMENDED)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Apply configured Argon2 function
 * 3) Produce encoded hash string
 * matches():
 * 1) Extract parameters from encoded hash
 * 2) Recompute hash using same parameters
 * 3) Perform secure comparison
 * ==========================================================================================
 * ENCODE FORMAT (STANDARD ARGON2)
 * ==========================================================================================
 * $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
 */
public class ARGON2_PASSWORD4J_PASSWORD_ENCODER_DEMO_V2 {

    private static final Logger logger = Logger.getLogger(ARGON2_PASSWORD4J_PASSWORD_ENCODER_DEMO_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== ARGON2 PASSWORD4J ENCODER DEMO V2 STARTED ==========");
        try {

            // ==================================================================================
            // STEP 1: CREATE FULLY CONFIGURED ARGON2 FUNCTION
            // ==================================================================================
            Argon2Function argon2Function = Argon2Function.getInstance(
                    65536,       // memory (64 MB)
                    3,           // iterations (time cost)
                    1,           // parallelism (threads)
                    32,          // output length (bytes)
                    Argon2.ID,   // Argon2id (recommended hybrid variant)
                    19           // version 1.3 (0x13)
            );

            logger.info("Custom Argon2Function created with full configuration.");
            // ==================================================================================
            // STEP 2: CREATE ENCODER
            // ==================================================================================
            Argon2Password4jPasswordEncoder argon2Password4jPasswordEncoder = new Argon2Password4jPasswordEncoder(argon2Function);
            logger.info("Argon2Password4jPasswordEncoder initialized.");

            // ==================================================================================
            // STEP 3: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 4: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = argon2Password4jPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = argon2Password4jPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = argon2Password4jPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 7: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = argon2Password4jPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * ✔ Different hashes due to random salt
             * ✔ Same Argon2 configuration embedded in hash
             * ✔ Verification works because parameters are stored in encoded string
             */
            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in Argon2Password4jPasswordEncoder demo V2", ex);
        }
    }
}