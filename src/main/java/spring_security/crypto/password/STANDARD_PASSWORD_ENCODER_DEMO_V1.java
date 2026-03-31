package spring_security.crypto.password;

import org.springframework.security.crypto.password.StandardPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * STANDARD_PASSWORD_ENCODER_DEMO_V1
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: StandardPasswordEncoder()
 * ==========================================================================================
 * CORE CONCEPT: SHA-256 BASED PASSWORD HASHING WITH SALT + SECRET (PEPPER)
 * ==========================================================================================
 * This encoder applies:
 * password + salt + secret → SHA-256 hash
 * ✔ Uses SHA-256 internally
 * ✔ Automatically generates salt
 * ✔ Supports secret (pepper)
 * ==========================================================================================
 * IMPORTANT NOTE (DEPRECATION)
 * ==========================================================================================
 * ❌ StandardPasswordEncoder is DEPRECATED
 * ❌ Not recommended for modern applications
 * WHY?
 * • No adaptive cost (fixed hashing)
 * • Fast → vulnerable to brute-force attacks
 * ✔ Replace with:
 * • BCryptPasswordEncoder
 * • Pbkdf2PasswordEncoder
 * • SCryptPasswordEncoder
 * • Argon2PasswordEncoder
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate random salt
 * 2) Combine: password + salt + secret
 * 3) Apply SHA-256
 * 4) Store salt + hash
 * matches():
 * 1) Extract salt
 * 2) Recompute hash
 * 3) Compare securely
 * ==========================================================================================
 * SECURITY CHARACTERISTICS
 * ==========================================================================================
 * ✔ Salted hashing
 * ✔ Supports secret (pepper)
 * ❌ No iteration (fixed cost)
 * ❌ No memory hardness
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * hex(salt + hash)
 */
public class STANDARD_PASSWORD_ENCODER_DEMO_V1 {

    private static final Logger logger = Logger.getLogger(STANDARD_PASSWORD_ENCODER_DEMO_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== STANDARD PASSWORD ENCODER DEMO V1 STARTED ==========");
        try {

            // ==================================================================================
            // STEP 1: CREATE ENCODER INSTANCE
            // ==================================================================================
            StandardPasswordEncoder standardPasswordEncoder = new StandardPasswordEncoder();
            logger.info("StandardPasswordEncoder initialized.");

            // ==================================================================================
            // STEP 2: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 3: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = standardPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 4: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = standardPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = standardPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 6: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = standardPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * ✔ Each encoding generates a new salt
             * ✔ Therefore, hashes will be DIFFERENT
             */
            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== STANDARD PASSWORD ENCODER DEMO V1 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in StandardPasswordEncoder demo V1", ex);
        }
    }
}