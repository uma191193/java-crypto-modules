package spring_security.crypto.password4j2;

import org.springframework.security.crypto.password4j.Pbkdf2Password4jPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * PBKDF2_PASSWORD4J_ENCODER_DEMO_V1
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: Pbkdf2Password4jPasswordEncoder()
 * ==========================================================================================
 * CORE CONCEPT: PBKDF2 (KEY DERIVATION FUNCTION)
 * ==========================================================================================
 * PBKDF2 (Password-Based Key Derivation Function 2) is a widely used algorithm for:
 * ✔ Secure password hashing
 * ✔ Key derivation using HMAC
 * ✔ Slowing down brute-force attacks via iterations
 * It is based on:
 * → HMAC (e.g., HmacSHA1 / HmacSHA256 / HmacSHA512)
 * ==========================================================================================
 * WHY USE PBKDF2?
 * ==========================================================================================
 * ✔ NIST recommended (legacy compliance)
 * ✔ Widely supported across platforms
 * ✔ Configurable iterations (adaptive)
 * HOWEVER:
 * ❌ Not memory-hard (unlike Argon2 / SCrypt / Balloon)
 * ==========================================================================================
 * DEFAULT CONSTRUCTOR BEHAVIOR
 * ==========================================================================================
 * Pbkdf2Password4jPasswordEncoder()
 * ✔ Uses Password4j’s default PBKDF2 configuration
 * ✔ Internally manages:
 * - Salt generation
 * - Iteration count
 * - Hash algorithm (typically HmacSHA256 or HmacSHA512)
 * ✔ No manual configuration required
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Apply PBKDF2 with HMAC
 * 3) Repeat hashing for defined iterations
 * 4) Produce encoded hash
 * matches():
 * 1) Extract parameters from encoded string
 * 2) Recompute hash using same salt + iterations
 * 3) Perform constant-time comparison
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * $pbkdf2$<algorithm>$<iterations>$<salt>$<hash>
 * (Exact format may vary depending on Password4j version)
 * ==========================================================================================
 * SECURITY CHARACTERISTICS
 * ==========================================================================================
 * ✔ Adaptive via iterations
 * ✔ Salted hashing
 * ✔ Standardized and well-tested
 * ❌ Not resistant to GPU attacks (no memory hardness)
 * ==========================================================================================
 * WHEN TO USE
 * ==========================================================================================
 * ✔ When compliance (e.g., NIST, FIPS) is required
 * ✔ When Argon2/BCrypt is unavailable
 * ✔ Cross-platform compatibility needs
 * ==========================================================================================
 * WHEN NOT TO USE
 * ==========================================================================================
 * ❌ High-security modern systems → prefer Argon2 / SCrypt
 */
public class PBKDF2_PASSWORD4J_ENCODER_DEMO_V1 {

    private static final Logger logger = Logger.getLogger(PBKDF2_PASSWORD4J_ENCODER_DEMO_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== PBKDF2 PASSWORD4J ENCODER DEMO V1 STARTED ==========");
        try {

            // ==================================================================================
            // STEP 1: CREATE ENCODER (DEFAULT CONFIGURATION)
            // ==================================================================================
            Pbkdf2Password4jPasswordEncoder pbkdf2Password4jPasswordEncoder = new Pbkdf2Password4jPasswordEncoder();
            logger.info("Pbkdf2Password4jPasswordEncoder initialized.");

            // ==================================================================================
            // STEP 2: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 3: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = pbkdf2Password4jPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 4: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = pbkdf2Password4jPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = pbkdf2Password4jPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 6: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = pbkdf2Password4jPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * ✔ Different hashes due to random salt
             * ✔ Same algorithm + iteration count used internally
             * ✔ Verification works because parameters are embedded
             */
            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in Pbkdf2Password4jPasswordEncoder demo V1", ex);
        }
    }
}