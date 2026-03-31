package spring_security.crypto.password;

import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * MESSAGE_DIGEST_PASSWORD_ENCODER_DEMO_V1
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: MessageDigestPasswordEncoder(String algorithm)
 * (Using SHA-256 Algorithm)
 * ==========================================================================================
 * CORE CONCEPT: MESSAGE DIGEST (ONE-WAY HASHING)
 * ==========================================================================================
 * This encoder applies standard hashing algorithms like:
 * ✔ MD5
 * ✔ SHA-1
 * ✔ SHA-256
 * password → digest → hex string
 * ==========================================================================================
 * CRITICAL LIMITATION
 * ==========================================================================================
 * ❌ No adaptive cost (unlike BCrypt/Argon2)
 * ❌ Fast hashing → vulnerable to brute-force
 * ❌ Optional salt (must be handled manually)
 * ==========================================================================================
 * ALGORITHM OPTIONS
 * ==========================================================================================
 * Common values for constructor:
 * "MD5"      → 128-bit (weak)
 * "SHA-1"    → 160-bit (broken)
 * "SHA-256"  → 256-bit (better but still not ideal)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Convert password → bytes
 * 2) Apply MessageDigest (based on algorithm)
 * 3) Convert result → HEX string
 * matches():
 * 1) Re-hash raw password
 * 2) Compare with stored hash
 * ==========================================================================================
 * OPTIONAL SALT SUPPORT
 * ==========================================================================================
 * This encoder supports salting via:
 * setEncodeHashAsBase64(boolean) and internal merging logic
 * BUT:
 * ❌ Salt is NOT automatically generated (developer responsibility)
 * ==========================================================================================
 * SECURITY WARNING
 * ==========================================================================================
 * ❌ Not resistant to GPU attacks
 * ❌ No memory hardness
 * ❌ Not adaptive
 * ✔ Replace with:
 * • BCryptPasswordEncoder
 * • Argon2PasswordEncoder
 * • SCryptPasswordEncoder
 */
public class MESSAGE_DIGEST_PASSWORD_ENCODER_DEMO_V1 {

    private static final Logger logger = Logger.getLogger(MESSAGE_DIGEST_PASSWORD_ENCODER_DEMO_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== MESSAGE DIGEST PASSWORD ENCODER DEMO STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: SELECT ALGORITHM
            // ==================================================================================
            String algorithm = "SHA-256"; // Try: MD5, SHA-1, SHA-256
            logger.info("Algorithm selected: " + algorithm);

            // ============================================================================= =====
            // STEP 2: CREATE ENCODER INSTANCE
            // ==================================================================================
            MessageDigestPasswordEncoder messageDigestPasswordEncoder = new MessageDigestPasswordEncoder(algorithm);
            logger.info("MessageDigestPasswordEncoder initialized.");

            // ==================================================================================
            // STEP 3: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 4: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = messageDigestPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = messageDigestPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = messageDigestPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 7: MULTIPLE HASH DEMO (IMPORTANT INSIGHT)
            // ==================================================================================
            String encodedAgain = messageDigestPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * If no salt is used → hashes will be SAME
             * If salt is used → hashes will differ
             */
            // ==================================================================================
            // STEP 8: COMPLETE
            // ==================================================================================
            logger.info("========== DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in MessageDigestPasswordEncoder demo", ex);
        }
    }
}