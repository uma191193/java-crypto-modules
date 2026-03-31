package spring_security.crypto.password;

import org.springframework.security.crypto.password.Md4PasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * MD4_Password_Encoder_Demo
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: Md4PasswordEncoder()
 * ==========================================================================================
 * CORE CONCEPT: LEGACY PASSWORD HASHING
 * ==========================================================================================
 * MD4 is a fast, outdated hashing algorithm:
 * password → MD4 hash
 * ❌ Not secure (vulnerable to collisions & brute-force)
 * ✔ Used only for legacy compatibility
 * ==========================================================================================
 * ALGORITHM DETAILS
 * ==========================================================================================
 * Name        : MD4
 * Output Size : 128-bit (16 bytes)
 * Speed       : Very fast (INSECURE for passwords)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * encode():
 * 1) Convert password → bytes
 * 2) Apply MD4 digest
 * 3) Return hex string
 * matches():
 * 1) Hash raw password again
 * 2) Compare with stored hash
 * ==========================================================================================
 * SECURITY WARNING
 * ==========================================================================================
 * ❌ MD4 is BROKEN
 * ❌ No salt
 * ❌ Extremely vulnerable to:
 * • Rainbow tables
 * • Brute force
 * ✔ Replace with:
 * • BCrypt
 * • Argon2
 * • SCrypt
 */
public class MD4_Password_Encoder_Demo {

    private static final Logger logger = Logger.getLogger(MD4_Password_Encoder_Demo.class.getName());

    public static void main(String[] args) {

        logger.info("========== MD4 PASSWORD ENCODER DEMO STARTED ==========");

        try {
            // ==================================================================================
            // STEP 1: CREATE ENCODER
            // ==================================================================================
            Md4PasswordEncoder md4PasswordEncoder = new Md4PasswordEncoder();
            logger.info("Md4PasswordEncoder initialized.");

            // ==================================================================================
            // STEP 2: DEFINE RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined.");

            // ==================================================================================
            // STEP 3: ENCODE (HASH)
            // ==================================================================================
            String encodedPassword = md4PasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password (MD4): " + encodedPassword);

            // ==================================================================================
            // STEP 4: VERIFY (CORRECT PASSWORD)
            // ==================================================================================
            boolean isMatch = md4PasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 5: VERIFY (WRONG PASSWORD)
            // ==================================================================================
            boolean isWrongMatch = md4PasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 6: COMPLETE
            // ==================================================================================
            logger.info("========== MD4 DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in MD4 Password Encoder demo", ex);
        }
    }
}