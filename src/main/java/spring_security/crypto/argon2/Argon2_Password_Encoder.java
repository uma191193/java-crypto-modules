package spring_security.crypto.argon2;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Argon2_Password_Encoder
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: Argon2PasswordEncoder(int saltLength, int hashLength, int parallelism, int memory, int iterations)
 * ==========================================================================================
 * CORE CONCEPT: PASSWORD HASHING (ONE-WAY FUNCTION)
 * ==========================================================================================
 * Argon2 is NOT encryption. It is a one-way key derivation function:
 * password → hash (irreversible)
 * ✔ You CANNOT retrieve original password from hash
 * ✔ You ONLY verify using matches()
 * This is fundamental to secure authentication systems.
 * ==========================================================================================
 * WHY ARGON2? (MODERN PASSWORD HASHING STANDARD)
 * ==========================================================================================
 * Argon2 (winner of Password Hashing Competition) is designed to resist:
 * ✔ Brute-force attacks
 * ✔ GPU-based cracking (parallel hardware)
 * ✔ ASIC-based attacks (specialized chips)
 * It achieves this using:
 * 1) MEMORY HARDNESS
 * → Requires large RAM → slows attackers significantly
 * 2) CPU COST (iterations)
 * → Increases computation time
 * 3) PARALLELISM CONTROL
 * → Balances CPU utilization
 * ==========================================================================================
 * PARAMETER BREAKDOWN (VERY IMPORTANT FOR SECURITY TUNING)
 * ==========================================================================================
 * 1) saltLength (bytes)
 * → Random value generated per password
 * → Ensures SAME password ≠ SAME hash
 * → Prevents rainbow table attacks
 * 2) hashLength (bytes)
 * → Final derived key size
 * → Larger = more entropy (but diminishing returns after ~32 bytes)
 * 3) parallelism (lanes)
 * → Number of parallel threads used internally
 * → Impacts CPU usage (not security significantly)
 * 4) memory (KB)
 * → MOST CRITICAL PARAMETER
 * → Defines how much RAM is required
 * → Example: 65536 = 64 MB
 * ✔ Higher memory = stronger resistance to GPU attacks
 * ❗ Too high = may impact server performance
 * 5) iterations (time cost)
 * → Number of passes over memory
 * → Increases computation time linearly
 * ✔ Higher iterations = slower hashing = more secure
 * ==========================================================================================
 * INTERNAL ENCODING FORMAT (VERY IMPORTANT)
 * ==========================================================================================
 * Spring stores the hash in this structured format:
 * $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
 * Breakdown:
 * argon2id → Algorithm variant (recommended)
 * v=19     → Version
 * m=65536  → Memory cost
 * t=3      → Iterations
 * p=1      → Parallelism
 * salt     → Base64 encoded random salt
 * hash     → Base64 encoded derived key
 * ✔ All parameters are EMBEDDED → no need to store separately
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * ENCODE (Hash Generation):
 * ----------------------------------------
 * 1) Generate cryptographically secure random salt
 * 2) Apply Argon2 algorithm with configured parameters
 * 3) Produce structured encoded string (see above)
 * MATCH (Verification):
 * ----------------------------------------
 * 1) Extract parameters + salt from stored hash
 * 2) Re-run Argon2 with SAME parameters
 * 3) Perform constant-time comparison
 * ✔ Prevents timing attacks
 * ==========================================================================================
 * IMPORTANT IMPLEMENTATION DETAIL
 * ==========================================================================================
 * encode() → PUBLIC API
 * ✔ Handles null checks
 * ✔ Delegates to internal method
 * encodeNonNullPassword() → INTERNAL
 * ✔ Actual hashing logic
 * Same applies for:
 * matches() → matchesNonNull()
 * ==========================================================================================
 * SECURITY BEST PRACTICES
 * ==========================================================================================
 * ✔ Always store ONLY encoded password
 * ✔ NEVER log raw passwords (only for demo here)
 * ✔ Use strong memory settings (>= 64MB in production)
 * ✔ Tune parameters based on server capacity
 * ✔ Recommended:
 * memory     = 65536 (64MB) or higher
 * iterations = 3+
 * saltLength = 16+
 * ==========================================================================================
 * WHEN TO UPGRADE HASH?
 * ==========================================================================================
 * If system policy changes (e.g., increase memory/iterations),
 * use:
 * encoder.upgradeEncoding(existingHash)
 * → If true → re-hash password on next login
 */
public class Argon2_Password_Encoder {

    private static final Logger logger = Logger.getLogger(Argon2_Password_Encoder.class.getName());

    public static void main(String[] args) {
        logger.info("========== ARGON2 PASSWORD ENCODER DEMO STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: CONFIGURE ARGON2 PARAMETERS
            // ==================================================================================
            // These values directly impact:
            //   • Security strength
            //   • CPU usage
            //   • Memory consumption
            int saltLength = 16;     // 16 bytes → standard secure salt size
            int hashLength = 32;     // 32 bytes → sufficient entropy
            int parallelism = 1;     // single-thread (safe default)
            int memory = 65536;      // 64 MB → strong defense against GPU attacks
            int iterations = 3;      // moderate time cost
            logger.info("Argon2 parameters configured.");
            // ==================================================================================
            // STEP 2: CREATE ENCODER INSTANCE
            // ==================================================================================
            // This object encapsulates:
            //   • Argon2 algorithm configuration
            //   • Salt generation
            //   • Hashing + verification logic
            Argon2PasswordEncoder argon2PasswordEncoder =
                    new Argon2PasswordEncoder(
                            saltLength,
                            hashLength,
                            parallelism,
                            memory,
                            iterations
                    );
            logger.info("Argon2PasswordEncoder instance created.");

            // ==================================================================================
            // STEP 3: DEFINE RAW PASSWORD
            // ==================================================================================
            // In real applications:
            //   ❗ NEVER hardcode passwords
            //   ❗ NEVER log raw passwords
            String rawPassword = "MySecurePassword@123";
            logger.info("Raw password defined (for demo only).");
            // ==================================================================================
            // STEP 4: ENCODE (HASH PASSWORD)
            // ==================================================================================
            // Internally:
            //   encode()
            //       → validation
            //       → encodeNonNullPassword()
            //       → Argon2 hashing
            String encodedPassword = argon2PasswordEncoder.encode(rawPassword);
            logger.info("Encoded Password: " + encodedPassword);

            // ==================================================================================
            // STEP 5: VERIFY PASSWORD (CORRECT CASE)
            // ==================================================================================
            // matches():
            //   → extracts parameters from encoded string
            //   → recomputes hash
            //   → constant-time comparison
            boolean isMatch = argon2PasswordEncoder.matches(rawPassword, encodedPassword);
            logger.info("Password Match (Correct): " + isMatch);

            // ==================================================================================
            // STEP 6: VERIFY PASSWORD (INCORRECT CASE)
            // ==================================================================================
            // Demonstrates failure scenario
            boolean isWrongMatch = argon2PasswordEncoder.matches("WrongPassword", encodedPassword);
            logger.info("Password Match (Wrong): " + isWrongMatch);

            // ==================================================================================
            // STEP 7: COMPLETION
            // ==================================================================================
            logger.info("========== ARGON2 DEMO COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            // Possible issues:
            //   • Invalid parameter configuration
            //   • Memory constraints
            logger.log(Level.SEVERE, "Error in Argon2 Password Encoder demo", ex);
        }
    }
}