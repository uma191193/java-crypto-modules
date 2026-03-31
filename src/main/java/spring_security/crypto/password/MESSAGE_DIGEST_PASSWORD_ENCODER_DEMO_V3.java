package spring_security.crypto.password;

import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * MESSAGE_DIGEST_PASSWORD_ENCODER_DEMO_V3
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: MessageDigestPasswordEncoder(String algorithm)
 * (Using MD5 Algorithm)
 * ==========================================================================================
 * CORE CONCEPT: MESSAGE DIGEST (ONE-WAY HASHING)
 * ==========================================================================================
 * This encoder applies standard hashing algorithms like:
 * ✔ MD5
 * ✔ SHA-1
 * ✔ SHA-256
 * password → digest → hex string
 * ==========================================================================================
 * MD5 SPECIFIC DETAILS
 * ==========================================================================================
 * Algorithm   : MD5
 * Output Size : 128-bit (16 bytes)
 * ❌ Cryptographically BROKEN
 * ❌ Extremely vulnerable to collisions
 * ❌ Very fast → HIGHLY vulnerable to brute-force attacks
 * ==========================================================================================
 * CRITICAL LIMITATION
 * ==========================================================================================
 * ❌ No adaptive cost (unlike BCrypt/Argon2)
 * ❌ Fast hashing → insecure for passwords
 * ❌ Optional salt (must be handled manually)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Convert password → bytes
 * 2) Apply MD5 digest
 * 3) Convert result → HEX string
 * matches():
 * 1) Re-hash raw password
 * 2) Compare with stored hash
 * ==========================================================================================
 * IMPORTANT BEHAVIOR
 * ==========================================================================================
 * MD5 is deterministic:
 * Same input → Same output (if no salt used)
 * ==========================================================================================
 * SECURITY WARNING
 * ==========================================================================================
 * ❌ MD5 is completely broken
 * ❌ Not suitable for ANY security use
 * ❌ Easily crackable using modern hardware
 * ✔ Replace with:
 * • BCryptPasswordEncoder
 * • Argon2PasswordEncoder
 * • SCryptPasswordEncoder
 */
public class MESSAGE_DIGEST_PASSWORD_ENCODER_DEMO_V3 {

    private static final Logger logger = Logger.getLogger(MESSAGE_DIGEST_PASSWORD_ENCODER_DEMO_V3.class.getName());

    public static void main(String[] args) {

        logger.info("========== MESSAGE DIGEST PASSWORD ENCODER DEMO V3 STARTED ==========");

        try {
            // ==================================================================================
            // STEP 1: SELECT ALGORITHM (MD5)
            // ==================================================================================
            String algorithm = "MD5";
            logger.info("Algorithm selected: " + algorithm);

            // ==================================================================================
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
            logger.info("Encoded Password (MD5): " + encodedPassword);

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
             * ✔ MD5 without salt → SAME hash every time
             * ❌ Makes system highly vulnerable to rainbow table attacks
             */

            // ==================================================================================
            // STEP 8: COMPLETE
            // ==================================================================================
            logger.info("========== DEMO V3 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in MessageDigestPasswordEncoder demo V3", ex);
        }
    }
}