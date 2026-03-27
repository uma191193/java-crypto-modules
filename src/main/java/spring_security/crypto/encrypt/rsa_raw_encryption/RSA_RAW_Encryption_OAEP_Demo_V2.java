package spring_security.crypto.encrypt.rsa_raw_encryption;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_RAW_Encryption_OAEP_Demo_V2
 * ------------------------------------------------------------------
 * This program demonstrates secure RSA encryption and decryption
 * using OAEP (Optimal Asymmetric Encryption Padding).
 * Unlike RAW RSA (V1), OAEP introduces randomness and padding,
 * making encryption semantically secure and suitable for real-world use
 * (within RSA size limitations).
 * ------------------------------------------------------------------
 * ENCRYPTION LIFECYCLE
 * ------------------------------------------------------------------
 * 1) RSA Key Pair Generation - Generates mathematically linked public and private keys.
 * 2) Cipher Initialization with OAEP - Configures RSA algorithm with padding and hashing.
 * 3) Plaintext Preparation - Converts input data into byte format.
 * 4) Encryption - Uses public key to securely transform plaintext → ciphertext.
 * 5) Decryption - Uses private key to recover original plaintext.
 * 6) Integrity Verification - Confirms decrypted output matches original input.
 * 7) Non-Determinism Demonstration - Shows that repeated encryption produces different ciphertexts.
 * ------------------------------------------------------------------
 * CRYPTOGRAPHIC ARCHITECTURE
 * ------------------------------------------------------------------
 * Plaintext
 * │
 * ▼
 * RSA + OAEP Padding (Public Key)
 * │
 * ▼
 * Ciphertext (Randomized)
 * │
 * ▼
 * RSA + OAEP Unpadding (Private Key)
 * │
 * ▼
 * Original Plaintext
 * ------------------------------------------------------------------
 * WHAT IS OAEP?
 * ------------------------------------------------------------------
 * OAEP = Optimal Asymmetric Encryption Padding
 * It enhances RSA security using:
 * • Hash Function (SHA-256)
 * - Creates fixed-length digest
 * - Used in padding structure
 * • MGF1 (Mask Generation Function)
 * - Expands randomness into masks
 * - Obscures plaintext patterns
 * • Random Seed
 * - Ensures different ciphertext each time
 * Result:
 * ✔ Non-deterministic encryption
 * ✔ Protection against chosen-plaintext attacks
 * ✔ Strong semantic security
 * ------------------------------------------------------------------
 * TRANSFORMATION BREAKDOWN
 * ------------------------------------------------------------------
 * "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
 * • RSA      → Asymmetric algorithm
 * • ECB      → Placeholder (not used like symmetric ECB)
 * • OAEP     → Padding scheme
 * • SHA-256  → Hash function inside OAEP
 * • MGF1     → Mask generation function
 * ------------------------------------------------------------------
 * SECURITY IMPROVEMENTS OVER V1
 * ------------------------------------------------------------------
 * V1 (RAW RSA):
 * ❌ No padding
 * ❌ Deterministic output
 * ❌ Vulnerable to attacks
 * V2 (RSA + OAEP):
 * ✔ Randomized ciphertext
 * ✔ Resistant to known attacks
 * ✔ Safe for encrypting small secrets (e.g., keys)
 * ------------------------------------------------------------------
 * IMPORTANT LIMITATIONS
 * ------------------------------------------------------------------
 * • RSA has size constraints:
 * For 2048-bit key:
 * - Max plaintext ≈ ~190–214 bytes (with OAEP)
 * • RSA is computationally expensive
 * • NOT suitable for:
 * - Large files
 * - Streaming data
 * ✔ Recommended usage:
 * Encrypt symmetric keys (used in Hybrid Encryption - V3)
 */
public class RSA_RAW_Encryption_OAEP_Demo_V2 {

    private static final Logger logger = Logger.getLogger(RSA_RAW_Encryption_OAEP_Demo_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA OAEP ENCRYPTION DEMO STARTED ==========");
        try {

            //--------------------------------------------------------------
            // STEP 1: GENERATE RSA KEY PAIR
            //--------------------------------------------------------------
            // RSA key generation process:
            // • Select two large prime numbers
            // • Compute modulus (n = p × q)
            // • Generate:
            //     - Public Key  (n, e) → encryption
            //     - Private Key (n, d) → decryption
            // Key size (2048 bits):
            // • Industry standard baseline
            // • Provides strong security

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            logger.info("RSA key pair generated.");

            //--------------------------------------------------------------
            // STEP 2: INITIALIZE CIPHER WITH OAEP
            //--------------------------------------------------------------
            // Cipher configuration:
            // Encryption:
            // • Uses PUBLIC key
            // • Applies OAEP padding before encryption
            // Decryption:
            // • Uses PRIVATE key
            // • Removes OAEP padding after decryption
            // OAEP ensures:
            // • Same plaintext → different ciphertext every time

            Cipher encryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

            Cipher decryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            logger.info("Cipher initialized with OAEP padding.");

            //--------------------------------------------------------------
            // STEP 3: PREPARE PLAINTEXT
            //--------------------------------------------------------------
            // Convert string → byte[]
            // Reason:
            // • Cryptographic APIs operate on binary data
            // UTF-8:
            // • Standard encoding
            // • Ensures consistent byte representation

            String sensitiveData = "RSA OAEP Secure Encryption Example 2026";
            Objects.requireNonNull(sensitiveData);

            byte[] plaintext = sensitiveData.getBytes(StandardCharsets.UTF_8);

            //--------------------------------------------------------------
            // STEP 4: ENCRYPT
            //--------------------------------------------------------------
            // Encryption flow:
            // plaintext
            //    │
            // OAEP padding (randomized)
            //    │
            // RSA encryption (public key)
            //    │
            // ciphertext
            // Output is binary → encoded using Base64

            byte[] ciphertext = encryptCipher.doFinal(plaintext);
            String encoded = Base64.getEncoder().encodeToString(ciphertext);

            logger.info("Ciphertext (Base64): " + encoded);

            //--------------------------------------------------------------
            // STEP 5: DECRYPT
            //--------------------------------------------------------------
            // Decryption flow:
            // ciphertext
            //    │
            // RSA decryption (private key)
            //    │
            // Remove OAEP padding
            //    │
            // original plaintext

            byte[] decrypted = decryptCipher.doFinal(ciphertext);
            String result = new String(decrypted, StandardCharsets.UTF_8);

            logger.info("Decrypted text: " + result);

            //--------------------------------------------------------------
            // STEP 6: VERIFY INTEGRITY
            //--------------------------------------------------------------
            // Simple equality check:
            // NOTE:
            // • This is NOT cryptographic integrity (no MAC/signature)
            // • Only validates correctness of round-trip encryption

            logger.info("Integrity: " + sensitiveData.equals(result));

            //--------------------------------------------------------------
            // STEP 7: NON-DETERMINISM DEMONSTRATION
            //--------------------------------------------------------------
            // Critical difference from V1:
            // Same plaintext encrypted again:
            // • Produces DIFFERENT ciphertext
            // Reason:
            // • OAEP introduces randomness via padding

            byte[] ciphertext2 = encryptCipher.doFinal(plaintext);
            String encoded2 = Base64.getEncoder().encodeToString(ciphertext2);

            logger.info("Second ciphertext: " + encoded2);
            logger.info("Different outputs (expected): " + !encoded.equals(encoded2));

            logger.info("========== RSA OAEP DEMO COMPLETED ==========");

        } catch (Exception ex) {
            //--------------------------------------------------------------
            // EXCEPTION HANDLING
            //--------------------------------------------------------------
            // Covers:
            // • Cipher initialization failures
            // • Invalid key usage
            // • Encryption/decryption errors
            //--------------------------------------------------------------
            logger.log(Level.SEVERE, "Error in RSA OAEP workflow", ex);
        }
    }
}