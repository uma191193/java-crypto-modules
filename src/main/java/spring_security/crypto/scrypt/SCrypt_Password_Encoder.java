package spring_security.crypto.scrypt;

import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * SCrypt_Password_Encoder
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: SCryptPasswordEncoder(int cpuCost, int memoryCost, int parallelization, int keyLength, int saltLength)
 * ==========================================================================================
 * CORE CONCEPT: MEMORY-HARD PASSWORD HASHING
 * ==========================================================================================
 * SCrypt is a one-way password hashing algorithm designed to be:
 * ✔ Memory-intensive
 * ✔ CPU-intensive
 * This makes it resistant to:
 * • Brute-force attacks
 * • GPU/ASIC cracking
 * ==========================================================================================
 * PARAMETER BREAKDOWN
 * ==========================================================================================
 * 1) cpuCost (N)
 * → CPU/Memory cost parameter (must be power of 2)
 * → Example: 2^14 = 16384
 * ✔ Higher = more secure
 * ❗ Too high = slow system performance
 * 2) memoryCost (r)
 * → Block size parameter
 * → Affects memory usage linearly
 * 3) parallelization (p)
 * → Parallel threads
 * → Improves performance, not security significantly
 * 4) keyLength
 * → Length of derived key (hash output)
 * 5) saltLength
 * → Random salt size (bytes)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * ENCODE:
 * 1) Generate random salt
 * 2) Apply SCrypt (CPU + memory intensive)
 * 3) Store encoded result
 * MATCH:
 * 1) Extract parameters + salt
 * 2) Recompute SCrypt
 * 3) Constant-time comparison
 * ==========================================================================================
 * OUTPUT FORMAT
 * ==========================================================================================
 * Spring stores SCrypt hash as:
 * $e0801$<salt>$<hash>
 * (Format may vary internally but includes parameters + salt)
 * ==========================================================================================
 * SECURITY NOTES
 * ==========================================================================================
 * ✔ One-way hashing (NO decryption)
 * ✔ Salt automatically handled
 * ✔ Resistant to hardware attacks
 */
public class SCrypt_Password_Encoder {

    private static final Logger logger = Logger.getLogger(SCrypt_Password_Encoder.class.getName());

    public static void main(String[] args) {

        logger.info("========== SCRYPT PASSWORD ENCODER DEMO V1 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: CONFIGURATION
            // ==================================================================================
            int cpuCost = 16384;       // N (2^14)
            int memoryCost = 8;        // r
            int parallelization = 1;   // p
            int keyLength = 32;        // output hash length
            int saltLength = 16;       // salt size
            logger.info("SCrypt parameters configured.");
            // ==================================================================================
            // STEP 2: CREATE ENCODER
            // ==================================================================================
            SCryptPasswordEncoder sCryptPasswordEncoder = new SCryptPasswordEncoder(
                    cpuCost,
                    memoryCost,
                    parallelization,
                    keyLength,
                    saltLength);
            logger.info("SCryptPasswordEncoder instance created.");

            // ==================================================================================
            // STEP 3: RAW PASSWORD
            // ==================================================================================
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined (demo only).");

            // ==================================================================================
            // STEP 4: ENCODE
            // ==================================================================================
            String encodedPassword = sCryptPasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 5: MATCH (CORRECT)
            // ==================================================================================
            boolean isMatch = sCryptPasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: MATCH (WRONG)
            // ==================================================================================
            boolean isWrongMatch = sCryptPasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 7: COMPLETE
            // ==================================================================================
            logger.info("========== SCRYPT DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            logger.log(Level.SEVERE, "Error in SCrypt Password Encoder demo", ex);
        }
    }
}
