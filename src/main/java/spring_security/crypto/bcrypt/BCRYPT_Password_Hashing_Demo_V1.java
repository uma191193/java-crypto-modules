package spring_security.crypto.bcrypt;

import org.springframework.security.crypto.bcrypt.BCrypt;

import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * BCRYPT_Password_Hashing_Demo_V1
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of BCrypt low-level API:
 * ✔ gensalt(String prefix, int log_rounds, SecureRandom random)
 * ✔ hashpw(String password, String salt)
 * ✔ checkpw(String plaintext, String hashed)
 * ==========================================================================================
 * CORE CONCEPT: ADAPTIVE PASSWORD HASHING
 * ==========================================================================================
 * BCrypt is a one-way password hashing algorithm:
 * password → hash (irreversible)
 * ✔ Designed to be slow (adaptive)
 * ✔ Includes built-in salt
 * ✔ Resistant to brute-force attacks
 * ==========================================================================================
 * WHY USE BCrypt?
 * ==========================================================================================
 * ✔ Automatically generates salt
 * ✔ Embeds salt + cost in hash
 * ✔ Widely used and battle-tested
 * ==========================================================================================
 * METHOD BREAKDOWN
 * ==========================================================================================
 * 1) gensalt(prefix, log_rounds, random)
 * → Generates salt string
 * prefix:
 * "$2a", "$2b", "$2y"
 * ✔ "$2a" → standard (used here)
 * log_rounds:
 * Cost factor (work factor)
 * Actual iterations = 2^log_rounds
 * Example:
 * log_rounds = 10 → 1024 rounds
 * SecureRandom:
 * Cryptographically secure random generator
 * ------------------------------------------------------------------------------------------
 * 2) hashpw(password, salt)
 * → Generates BCrypt hash
 * Internally:
 * • Applies Blowfish-based hashing
 * • Uses salt + cost factor
 * • Produces encoded hash string
 * ------------------------------------------------------------------------------------------
 * → Verifies password
 * Internally:
 * • Extract salt + cost from stored hash
 * • Recomputes hash
 * • Performs constant-time comparison
 * ==========================================================================================
 * HASH FORMAT
 * ==========================================================================================
 * Example:
 * $2a$10$<22charSalt><31charHash>
 * Breakdown:
 * $2a  → Algorithm version
 * 10   → Cost factor (log_rounds)
 * salt → Embedded salt
 * hash → Final hash
 * ==========================================================================================
 * SECURITY NOTES
 * ==========================================================================================
 * ✔ One-way hashing (NO decryption)
 * ✔ Salt is automatically handled
 * ✔ Cost factor controls security strength
 */
public class BCRYPT_Password_Hashing_Demo_V1 {

    private static final Logger logger = Logger.getLogger(BCRYPT_Password_Hashing_Demo_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== BCRYPT PASSWORD HASHING DEMO V1 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: CONFIGURE PARAMETERS
            // ==================================================================================
            String prefix = "$2a";       // BCrypt version
            int logRounds = 10;          // cost factor (2^10 = 1024 iterations)
            // Secure random generator
            SecureRandom secureRandom = new SecureRandom();
            logger.info("BCrypt parameters configured.");

            // ==================================================================================
            // STEP 2: GENERATE SALT
            // ==================================================================================
            // Salt includes:
            //   • algorithm version
            //   • cost factor
            //   • random value
            String salt = BCrypt.gensalt(prefix, logRounds, secureRandom);
            logger.info("Generated Salt: " + salt);
            // ==================================================================================
            // STEP 3: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined (demo only).");
            // ==================================================================================
            // STEP 4: HASH PASSWORD
            // ==================================================================================
            // hashpw():
            //   • uses salt
            //   • applies BCrypt algorithm
            //   • embeds salt + cost in result
            String hashedPassword = BCrypt.hashpw(rawPassword, salt);
            logger.info("Hashed Password: " + hashedPassword);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (CORRECT CASE)
            // ==================================================================================
            boolean isMatch = BCrypt.checkpw(rawPassword, hashedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: VERIFY PASSWORD (WRONG CASE)
            // ==================================================================================
            boolean isWrongMatch = BCrypt.checkpw("WrongPassword", hashedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 7: COMPLETION
            // ==================================================================================
            logger.info("========== BCRYPT DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in BCrypt Password Hashing demo", ex);
        }
    }
}
