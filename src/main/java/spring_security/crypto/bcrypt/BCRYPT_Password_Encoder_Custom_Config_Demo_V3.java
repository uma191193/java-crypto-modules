package spring_security.crypto.bcrypt;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * BCRYPT_Password_Encoder_Custom_Config_Demo_V3
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: BCryptPasswordEncoder(BCryptVersion version, int strength, SecureRandom random)
 * ==========================================================================================
 * CORE CONCEPT: FULL CONTROL OVER BCRYPT CONFIGURATION
 * ==========================================================================================
 * This constructor allows fine-grained control over:
 * ✔ Algorithm version (prefix)
 * ✔ Cost factor (strength)
 * ✔ Random source (SecureRandom)
 * ==========================================================================================
 * PARAMETER BREAKDOWN
 * ==========================================================================================
 * 1) BCryptVersion version
 * → Defines algorithm prefix in hash
 * Available:
 * • $2a → Standard
 * • $2b → Improved (recommended)
 * • $2y → Compatibility variant
 * ------------------------------------------------------------------------------------------
 * 2) strength (log rounds)
 * → Cost factor controlling computation time
 * Actual iterations = 2^strength
 * Example:
 * strength = 12 → 4096 rounds
 * ✔ Higher = stronger but slower
 * ------------------------------------------------------------------------------------------
 * 3) SecureRandom random
 * → Source of randomness for salt generation
 * ✔ Cryptographically secure
 * ✔ Ensures unique salt per password
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Generate salt using SecureRandom
 * 2) Apply BCrypt hashing with chosen version + strength
 * 3) Embed version + cost + salt into final hash
 * matches():
 * 1) Extract version + cost + salt from hash
 * 2) Recompute hash
 * 3) Constant-time comparison
 * ==========================================================================================
 * HASH FORMAT
 * ==========================================================================================
 * Example:
 * $2b$12$<22charSalt><31charHash>
 * Breakdown:
 * $2b → Version
 * 12  → Cost factor
 * salt+hash → Encoded data
 * ==========================================================================================
 * SECURITY NOTES
 * ==========================================================================================
 * ✔ One-way hashing (NO decryption)
 * ✔ Salt automatically embedded
 * ✔ Stronger than default when using higher strength
 */
public class BCRYPT_Password_Encoder_Custom_Config_Demo_V3 {

    private static final Logger logger = Logger.getLogger(BCRYPT_Password_Encoder_Custom_Config_Demo_V3.class.getName());

    public static void main(String[] args) {

        logger.info("========== BCRYPT PASSWORD ENCODER DEMO V3 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: CONFIGURE PARAMETERS
            // ==================================================================================
            // Recommended modern version
            BCryptPasswordEncoder.BCryptVersion version = BCryptPasswordEncoder.BCryptVersion.$2B;
            int strength = 12; // 2^12 = 4096 iterations (stronger than default)
            SecureRandom secureRandom = new SecureRandom();
            logger.info("Version: " + version);
            logger.info("Strength: " + strength);
            // ==================================================================================
            // STEP 2: CREATE ENCODER
            // ==================================================================================
            BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(version, strength, secureRandom);
            logger.info("BCryptPasswordEncoder initialized with custom configuration.");
            // ==================================================================================
            // STEP 3: RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined (demo only).");
            // ==================================================================================
            // STEP 4: ENCODE
            // ==================================================================================
            String encodedPassword = bCryptPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);
            // ==================================================================================
            // STEP 5: VERIFY (CORRECT)
            // ==================================================================================
            boolean isMatch = bCryptPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);
            // ==================================================================================
            // STEP 6: VERIFY (WRONG)
            // ==================================================================================
            boolean isWrongMatch = bCryptPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);
            // ==================================================================================
            // STEP 7: COMPLETE
            // ==================================================================================
            logger.info("========== BCRYPT DEMO V3 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in BCrypt Password Encoder demo V3", ex);
        }
    }
}
