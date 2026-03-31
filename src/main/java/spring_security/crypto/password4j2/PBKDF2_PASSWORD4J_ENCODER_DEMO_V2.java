package spring_security.crypto.password4j2;

import com.password4j.PBKDF2Function;
import org.springframework.security.crypto.password4j.Pbkdf2Password4jPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * PBKDF2_PASSWORD4J_ENCODER_DEMO_V2
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: Pbkdf2Password4jPasswordEncoder(PBKDF2Function pbkdf2Function, int saltLength)
 * ==========================================================================================
 * CORE CONCEPT: CUSTOM PBKDF2 CONFIGURATION (PASSWORD4J)
 * ==========================================================================================
 * Unlike V1 (default configuration), this allows FULL control over:
 * ✔ HMAC algorithm (SHA1 / SHA256 / SHA512)
 * ✔ Iteration count
 * ✔ Derived key length
 * ✔ Salt length
 * ==========================================================================================
 * WHY CUSTOM PBKDF2Function?
 * ==========================================================================================
 * ✔ Tune security vs performance
 * ✔ Meet compliance requirements (e.g., SHA256/SHA512)
 * ✔ Increase iteration count over time
 * ==========================================================================================
 * PBKDF2 PARAMETERS EXPLAINED
 * ==========================================================================================
 * algorithm
 * → HmacSHA1 / HmacSHA256 / HmacSHA512
 * iterations
 * → Number of hashing rounds (higher = stronger but slower)
 * length
 * → Derived key length (in bits)
 * saltLength
 * → Size of random salt (in bytes)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt (based on saltLength)
 * 2) Apply PBKDF2 with configured algorithm + iterations
 * 3) Produce encoded string
 * matches():
 * 1) Extract parameters (algorithm, iterations, salt)
 * 2) Recompute hash
 * 3) Perform constant-time comparison
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * $pbkdf2$<algorithm>$<iterations>$<salt>$<hash>
 * ==========================================================================================
 * SECURITY CHARACTERISTICS
 * ==========================================================================================
 * ✔ Adaptive via iterations
 * ✔ Salted hashing
 * ✔ Algorithm flexibility
 * ❌ Not memory-hard → weaker vs GPU/ASIC attacks
 * ==========================================================================================
 * RECOMMENDED SETTINGS
 * ==========================================================================================
 * ✔ Algorithm → HmacSHA256 or HmacSHA512
 * ✔ Iterations → 100,000+
 * ✔ Salt length → 16 bytes minimum
 */
public class PBKDF2_PASSWORD4J_ENCODER_DEMO_V2 {

    private static final Logger logger = Logger.getLogger(PBKDF2_PASSWORD4J_ENCODER_DEMO_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== PBKDF2 PASSWORD4J ENCODER DEMO V2 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: CREATE CUSTOM PBKDF2 FUNCTION
            // ==================================================================================
            PBKDF2Function pbkdf2Function = PBKDF2Function.getInstance(
                    "SHA256",   // algorithm
                    150000,         // iterations
                    256             // derived key length (bits)
            );

            logger.info("Custom PBKDF2Function created (HmacSHA256, 150000 iterations, 256-bit key).");

            // ==================================================================================
            // STEP 2: CREATE ENCODER WITH CUSTOM FUNCTION + SALT LENGTH
            // ==================================================================================
            int saltLength = 16; // bytes
            Pbkdf2Password4jPasswordEncoder pbkdf2Password4jPasswordEncoder =
                    new Pbkdf2Password4jPasswordEncoder(pbkdf2Function, saltLength);
            logger.info("Encoder initialized with custom PBKDF2 configuration.");

            // ==================================================================================
            // STEP 3: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 4: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = pbkdf2Password4jPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = pbkdf2Password4jPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = pbkdf2Password4jPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 7: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = pbkdf2Password4jPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * ✔ Different hashes due to random salt
             * ✔ Same algorithm + iteration count used internally
             * ✔ Salt length explicitly controlled (16 bytes)
             */

            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in Pbkdf2Password4jPasswordEncoder demo V2", ex);
        }
    }
}