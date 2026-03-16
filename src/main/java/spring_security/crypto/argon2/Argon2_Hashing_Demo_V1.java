package spring_security.crypto.argon2;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Argon2_Hashing_Demo_V1
 * ---------------------------------------------------------
 * This program demonstrates how to securely hash and verify
 * passwords using the Argon2 algorithm through Spring Security.
 * <p>
 * The demo walks through the full lifecycle of password hashing:
 * <p>
 * 1) Encoder Initialization
 * 2) Password Hashing (Encoding)
 * 3) Password Verification (Matching)
 * 4) Security Upgrade Detection
 * 5) Hash Format Inspection
 * <p>
 * Why Argon2?
 * ---------------------------------------------------------
 * Argon2 is a modern password hashing algorithm designed to be:
 * <p>
 * • Memory-Hard
 * • Resistant to GPU attacks
 * • Resistant to ASIC cracking
 * • Resistant to rainbow tables
 * <p>
 * It was the winner of the Password Hashing Competition (PHC)
 * and is currently considered one of the most secure password
 * hashing algorithms available.
 */
public class Argon2_Hashing_Demo_V1 {

    private static final Logger logger = Logger.getLogger(Argon2_Hashing_Demo_V1.class.getName());

    public static void main(String[] args) {

        try {

            // =============================================================
            // STEP 1: Initialize the Argon2 Encoder
            // =============================================================
            //
            // We initialize the argon2PasswordEncoder using Spring Security's recommended
            // configuration for Argon2 (introduced in Spring Security 5.8).
            //
            // Method: Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
            //
            // This factory method creates an Argon2 argon2PasswordEncoder configured with
            // secure default parameters suitable for modern hardware.
            //
            // Internally the following parameters are used:
            //
            //   saltLength   = 16 bytes
            //   hashLength   = 32 bytes
            //   parallelism  = 1 thread
            //   memory       = 65536 KB (64 MB)
            //   iterations   = 3
            //
            // Parameter meanings:
            //
            //   saltLength
            //      Random salt size added to the password before hashing.
            //      Prevents rainbow table attacks.
            //
            //   hashLength
            //      Length of the final generated hash output.
            //
            //   parallelism
            //      Number of CPU threads used during hashing.
            //
            //   memory
            //      Amount of RAM required to compute the hash.
            //      This makes attacks extremely expensive on GPUs.
            //
            //   iterations
            //      Number of hashing rounds performed.
            //
            // In most applications these defaults are recommended because they balance security and performance.
            // Manually can be declared as:
            // Argon2PasswordEncoder argon2PasswordEncoder =
            //        new Argon2PasswordEncoder(
            //                16,      // saltLength (bytes)
            //                32,      // hashLength (bytes)
            //                1,       // parallelism (threads)
            //                65536,   // memory (KB)
            //                3        // iterations
            //        );
            Argon2PasswordEncoder argon2PasswordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

            logger.info("=== Encoder Initialized ===");
            logger.info("Algorithm: Argon2id");

            // =============================================================
            // STEP 2: Password Encoding (Hash Generation)
            // =============================================================
            // In a real authentication system, this step happens during
            // USER REGISTRATION or PASSWORD CHANGE.
            //
            // Instead of storing the raw password, we store a HASH.
            //
            // The argon2PasswordEncoder performs the following internally:
            //
            //   1) Generate a random SALT
            //   2) Combine salt + password
            //   3) Apply Argon2 memory-hard hashing
            //   4) Encode parameters + salt + hash into one string
            // Important: The password is NEVER stored directly.
            //
            // encode()
            //   → null validation
            //   → encodeNonNullPassword()
            //        → generate random salt
            //        → apply Argon2 hashing
            //        → return PHC formatted string
            String rawPassword = "Post-Quantum-Secure-Password-2026";

            logger.info("Hashing the raw password...");

            String encodedHash = argon2PasswordEncoder.encode(rawPassword);
            // The generated hash contains multiple components:
            //
            //   Algorithm
            //   Version
            //   Memory cost
            //   Iterations
            //   Parallelism
            //   Salt
            //   Hash value
            //
            // Example structure (PHC format):
            //   $argon2id$v=19$m=65536,t=3,p=1$SALT$HASH
            //
            logger.info("Generated Hash: " + encodedHash);
            logger.info("Hash length (chars): " + encodedHash.length());

            // =============================================================
            // STEP 3: Password Verification (Matching)
            // =============================================================
            // During USER LOGIN we never decrypt the password.
            // Instead we:
            //   1) Take the user-provided password
            //   2) Extract parameters + salt from stored hash
            //   3) Hash the new input with the same parameters
            //   4) Compare both hashes
            //
            // matches()
            //   → validate parameters
            //   → matchesNonNull()
            //        → extract parameters from stored hash
            //        → recompute hash
            //        → compare result
            // If both match → authentication succeeds.
            //
            String testInput = "Post-Quantum-Secure-Password-2026";
            String wrongInput = "WrongPassword123";

            boolean isMatch = argon2PasswordEncoder.matches(testInput, encodedHash);
            boolean isWrongMatch = argon2PasswordEncoder.matches(wrongInput, encodedHash);

            logger.info("\n=== Verification Results ===");
            logger.info("Test with correct password: " + (isMatch ? "SUCCESS" : "FAIL"));
            logger.info("Test with wrong password  : " + (isWrongMatch ? "SUCCESS" : "FAIL"));

            // =============================================================
            // STEP 4: Adaptive Security (Upgrade Detection)
            // =============================================================
            // Security requirements evolve over time.
            //
            // Example:
            //   • hardware becomes faster
            //   • attackers get more compute power
            //
            // To maintain security, password hashing parameters must occasionally be strengthened.
            //
            // Spring Security provides: upgradeEncoding(hash)
            //
            // This checks if the stored hash was generated with
            // weaker parameters than the current argon2PasswordEncoder.

            // upgradeEncoding()
            //   → validate input
            //   → upgradeEncodingNonNull()
            //        → check if parameters differ from current encoder
            // If TRUE: the password should be rehashed after login
            boolean needsUpgrade = argon2PasswordEncoder.upgradeEncoding(encodedHash);

            logger.info("Does hash need security upgrade? " + needsUpgrade);

            // =============================================================
            // STEP 5: Inspect the Hash Structure
            // =============================================================
            // Argon2 hashes follow the PHC string format: $argon2id$v=19$m=65536,t=3,p=1$SALT$HASH
            // Breakdown:
            // argon2id  → algorithm variant
            // v=19      → Argon2 version
            // m=65536   → memory cost
            // t=3       → iterations
            // p=1       → parallelism
            // SALT      → random salt
            // HASH      → final encoded hash
            if (encodedHash.startsWith("$argon2id")) {
                logger.info("Verified: Hash uses Argon2id variant (recommended).");
            }

        } catch (Exception e) {
            logger.log(Level.SEVERE, "An unexpected error occurred: " + e.getMessage(), e);
        }
    }
}