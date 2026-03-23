package spring_security.crypto.encrypt;

import org.springframework.security.crypto.encrypt.RsaAlgorithm;
import org.springframework.security.crypto.encrypt.RsaRawEncryptor;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_RAW_Encryption_KeyPair_Algorithm_Demo_V9
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates advanced RSA encryption using: RsaRawEncryptor(KeyPair keyPair, RsaAlgorithm algorithm)
 * ------------------------------------------------------------------
 * CORE IDEA
 * ------------------------------------------------------------------
 * This demo shows how to:
 * ✔ Use RSA with explicit padding control (OAEP)
 * ✔ Avoid PEM parsing and work directly with key objects
 * ✔ Perform secure encryption/decryption using modern standards
 * ------------------------------------------------------------------
 * INTERNAL CRYPTOGRAPHIC BEHAVIOR
 * ------------------------------------------------------------------
 * When using: RsaAlgorithm.OAEP
 * Internally maps to JCE transformation: "RSA/ECB/OAEPWithSHA-1AndMGF1Padding" (provider dependent)
 * Components involved:
 * • RSA → Asymmetric encryption algorithm
 * • OAEP → Padding scheme providing semantic security
 * • MGF1 → Mask Generation Function (adds randomness)
 * ------------------------------------------------------------------
 * WHY OAEP IS CRITICAL
 * ------------------------------------------------------------------
 * Without OAEP (PKCS#1 v1.5):
 * ❌ Deterministic encryption
 * ❌ Vulnerable to padding oracle attacks
 * With OAEP:
 * ✔ Randomized encryption (same plaintext ≠ same ciphertext)
 * ✔ Stronger against chosen plaintext attacks
 * ✔ Industry standard (TLS, secure key exchange)
 * ------------------------------------------------------------------
 * LIMITATION OF RSA (IMPORTANT)
 * ------------------------------------------------------------------
 * RSA is NOT designed for bulk data encryption.
 * For 2048-bit RSA: Max payload ≈ 190 bytes (with OAEP)
 * Reason: Padding + mathematical constraints reduce usable size
 * ------------------------------------------------------------------
 * PRODUCTION NOTE
 * ------------------------------------------------------------------
 * Real-world systems use:
 * ✔ RSA → Encrypt AES key
 * ✔ AES-GCM → Encrypt actual data
 * (Hybrid Encryption Model)
 */
public class RSA_RAW_Encryption_KeyPair_Algorithm_Demo_V9 {

    private static final Logger logger = Logger.getLogger(RSA_RAW_Encryption_KeyPair_Algorithm_Demo_V9.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA RAW KEYPAIR + ALGORITHM DEMO V9 STARTED ==========");
        try {
            //----------------------------------------------------------
            // STEP 1: GENERATE RSA KEY PAIR
            //----------------------------------------------------------
            // KeyPairGenerator is part of JCA (Java Cryptography Architecture)
            // "RSA" → selects RSA algorithm provider (SunRsaSign / BouncyCastle etc.)
            // 2048-bit:
            // ✔ Minimum recommended key size (as of modern standards)
            // ✔ Provides ~112-bit security strength
            // Internally: Generates modulus (n), public exponent (e), private exponent (d)

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            logger.info("RSA KeyPair generated.");
            logger.info("Public Key Format : " + keyPair.getPublic().getFormat());
            logger.info("Private Key Format: " + keyPair.getPrivate().getFormat());

            //----------------------------------------------------------
            // STEP 2: INITIALIZE ENCRYPTOR WITH ALGORITHM
            //----------------------------------------------------------
            // RsaRawEncryptor wraps low-level Cipher operations
            // Constructor: new RsaRawEncryptor(KeyPair, RsaAlgorithm)
            // Internally:
            // • Extracts public/private keys
            // • Configures Cipher instance
            // • Applies selected padding scheme
            // OAEP:
            // ✔ Adds randomness via padding
            // ✔ Uses hash + MGF1 internally

            RsaRawEncryptor rsaRawEncryptor = new RsaRawEncryptor(keyPair, RsaAlgorithm.OAEP);
            logger.info("Encryptor initialized with OAEP algorithm.");

            //----------------------------------------------------------
            // STEP 3: PREPARE DATA
            //----------------------------------------------------------
            // Convert String → byte[]
            // Why UTF-8?
            // ✔ Standard encoding
            // ✔ Cross-platform consistency
            // NOTE: RSA works only on byte arrays (not Strings)

            String data = "RSA KeyPair + OAEP Demo V9";
            Objects.requireNonNull(data);

            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);

            logger.info("Plaintext: " + data);
            logger.info("Plaintext Length (bytes): " + plaintext.length);

            //----------------------------------------------------------
            // STEP 4: ENCRYPT
            //----------------------------------------------------------
            // Encryption Flow: plaintext → OAEP padding → RSA math → ciphertext
            // Internally:
            // • Padding applied first
            // • Then modular exponentiation:
            //   c = m^e mod n
            // Output: Binary data (not human-readable)

            byte[] encrypted = rsaRawEncryptor.encrypt(plaintext);

            // Base64 encoding:
            // ✔ Converts binary → text-safe format
            // ✔ Used for transport/logging
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);

            logger.info("Encrypted Length (bytes): " + encrypted.length);
            logger.info("Encrypted (Base64): " + base64Cipher);

            //----------------------------------------------------------
            // STEP 5: DECRYPT
            //----------------------------------------------------------
            // Decryption Flow: ciphertext → RSA math → remove OAEP padding → plaintext
            // Internally:
            // • m = c^d mod n
            // • OAEP validation occurs
            // If tampered: ❌ Padding validation fails → Exception thrown

            byte[] decrypted = rsaRawEncryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted: " + decryptedText);

            //----------------------------------------------------------
            // STEP 6: VERIFY
            //----------------------------------------------------------
            // Logical equality check
            // IMPORTANT:
            // OAEP already guarantees:
            // ✔ Integrity (tampering detection)
            // ✔ Authenticity (to some extent)

            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check: " + isMatch);
            if (!isMatch) {
                logger.warning("Data mismatch detected!");
            }
            //----------------------------------------------------------
            // FINAL NOTE
            //----------------------------------------------------------
            // Even though this is secure:
            // ❌ Do NOT use RSA directly for large payloads
            // ✔ Use Hybrid Encryption:
            //    AES-GCM (data) + RSA-OAEP (key)
            logger.info("========== RSA RAW KEYPAIR + ALGORITHM DEMO V9 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible failures:
            // • IllegalBlockSizeException
            //   → Data too large for RSA
            // • BadPaddingException
            //   → Tampered ciphertext / wrong key
            // • NoSuchAlgorithmException
            //   → Missing crypto provider
            // • InvalidKeyException
            //   → Incorrect key usage
            logger.log(Level.SEVERE, "Error in RSA KeyPair + Algorithm Demo V9", ex);
        }
    }
}