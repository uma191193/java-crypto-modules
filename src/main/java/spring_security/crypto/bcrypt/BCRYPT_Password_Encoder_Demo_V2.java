package spring_security.crypto.bcrypt;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * BCRYPT_Password_Encoder_Demo_V2
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: BCryptPasswordEncoder()
 * ==========================================================================================
 * CORE CONCEPT: HIGH-LEVEL PASSWORD HASHING (WRAPPER OVER BCrypt)
 * ==========================================================================================
 * BCryptPasswordEncoder is a Spring Security wrapper around low-level BCrypt API.
 * ✔ Simplifies usage (no manual salt handling)
 * ✔ Secure defaults
 * ✔ Automatically manages:
 * • Salt generation
 * • Hashing
 * • Verification
 * ==========================================================================================
 * DEFAULT CONFIGURATION (IMPORTANT)
 * ==========================================================================================
 * Internally equivalent to:
 * prefix      → $2a
 * strength    → 10 (log rounds)
 * random      → SecureRandom
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate salt (internally)
 * 2) Apply BCrypt hashing
 * 3) Embed salt + cost into hash
 * matches():
 * 1) Extract salt + cost from stored hash
 * 2) Recompute hash
 * 3) Constant-time comparison
 * ==========================================================================================
 * HASH FORMAT
 * ==========================================================================================
 * Example:
 * $2a$10$<22charSalt><31charHash>
 * ==========================================================================================
 * SECURITY NOTES
 * ==========================================================================================
 * ✔ One-way hashing (NO decryption)
 * ✔ Salt handled automatically
 * ✔ Cost factor adjustable via other constructors
 */
public class BCRYPT_Password_Encoder_Demo_V2 {

    private static final Logger logger = Logger.getLogger(BCRYPT_Password_Encoder_Demo_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== BCRYPT PASSWORD ENCODER DEMO V2 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: CREATE ENCODER (DEFAULT CONFIG)
            // ==================================================================================
            BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
            logger.info("BCryptPasswordEncoder initialized with default strength (10).");

            // ==================================================================================
            // STEP 2: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined (demo only).");

            // ==================================================================================
            // STEP 3: ENCODE (HASH)
            // ==================================================================================
            String encodedPassword = bCryptPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 4: VERIFY (CORRECT)
            // ==================================================================================
            boolean isMatch = bCryptPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 5: VERIFY (WRONG)
            // ==================================================================================
            boolean isWrongMatch = bCryptPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 6: COMPLETE
            // ==================================================================================
            logger.info("========== BCRYPT DEMO V2 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in BCrypt Password Encoder demo V2", ex);
        }
    }
}