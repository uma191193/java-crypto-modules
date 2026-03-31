package spring_security.crypto.password;

import org.springframework.security.crypto.password.StandardPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * STANDARD_PASSWORD_ENCODER_DEMO_V2
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: StandardPasswordEncoder(CharSequence secret)
 * ==========================================================================================
 * CORE CONCEPT: SHA-256 HASHING WITH SALT + SECRET (PEPPER)
 * ==========================================================================================
 * This encoder applies:
 * password + salt + secret → SHA-256 hash
 * ✔ Salt → automatically generated
 * ✔ Secret (Pepper) → provided explicitly
 * ==========================================================================================
 * WHAT IS "SECRET" (PEPPER)?
 * ==========================================================================================
 * Secret (pepper) is:
 * ✔ Application-level secret key
 * ✔ NOT stored in database
 * ✔ Stored securely (env variable / vault / config server)
 * ==========================================================================================
 * WHY PEPPER IS IMPORTANT
 * ==========================================================================================
 * Even if DB is compromised:
 * ❌ Attacker has hash + salt
 * ✔ But NOT the secret → cannot recompute hash
 * ==========================================================================================
 * IMPORTANT NOTE (DEPRECATION)
 * ==========================================================================================
 * ❌ StandardPasswordEncoder is DEPRECATED
 * ❌ Not adaptive → vulnerable to brute-force
 * ✔ Prefer:
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
 * 2) Combine with same secret
 * 3) Recompute hash
 * 4) Compare securely
 * ==========================================================================================
 * CRITICAL REQUIREMENT
 * ==========================================================================================
 * ✔ SAME secret must be used for:
 * • encoding
 * • matching
 * Otherwise → authentication FAILS
 * ==========================================================================================
 * ENCODE FORMAT
 * ==========================================================================================
 * hex(salt + hash)
 */
public class STANDARD_PASSWORD_ENCODER_DEMO_V2 {

    private static final Logger logger = Logger.getLogger(STANDARD_PASSWORD_ENCODER_DEMO_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== STANDARD PASSWORD ENCODER DEMO V2 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: DEFINE SECRET (PEPPER)
            // ==================================================================================
            CharSequence secret = "ApplicationLevelSecretKey"; // Store securely outside DB
            logger.info("Secret (pepper) defined.");

            // ==================================================================================
            // STEP 2: CREATE ENCODER INSTANCE
            // ==================================================================================
            StandardPasswordEncoder standardPasswordEncoder = new StandardPasswordEncoder(secret);
            logger.info("StandardPasswordEncoder initialized with secret.");

            // ==================================================================================
            // STEP 3: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 4: ENCODE PASSWORD
            // ==================================================================================
            String encodedPassword = standardPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (CORRECT)
            // ==================================================================================
            boolean isMatch = standardPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: VERIFY PASSWORD (WRONG)
            // ==================================================================================
            boolean isWrongMatch = standardPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 7: MULTIPLE ENCODING INSIGHT
            // ==================================================================================
            String encodedAgain = standardPasswordEncoder.encode(rawPassword);
            logger.info("Re-encoded Password: " + encodedAgain);
            logger.info("Are both hashes same? " + encodedPassword.equals(encodedAgain));

            /**
             * Insight:
             * ✔ Different hashes due to random salt
             * ✔ Secret remains constant
             */

            // ==================================================================================
            // STEP 8: SECRET CONSISTENCY CHECK (IMPORTANT)
            // ==================================================================================
            StandardPasswordEncoder wrongEncoder = new StandardPasswordEncoder("WrongSecret");

            boolean wrongSecretMatch = wrongEncoder.matches(rawPassword, encodedPassword);
            logger.info("Match with WRONG secret: " + wrongSecretMatch);

            /**
             * Insight:
             * ❌ Using different secret → authentication fails
             */
            // ==================================================================================
            // COMPLETE
            // ==================================================================================
            logger.info("========== STANDARD PASSWORD ENCODER DEMO V2 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in StandardPasswordEncoder demo V2", ex);
        }
    }
}