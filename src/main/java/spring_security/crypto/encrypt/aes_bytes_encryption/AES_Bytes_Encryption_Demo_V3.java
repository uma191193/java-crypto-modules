package spring_security.crypto.encrypt.aes_bytes_encryption;

import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * AES_Bytes_Encryption_Demo_V3
 * -------------------------------------------------------------------------
 * This program demonstrates AES encryption using the following constructor:
 * <p>
 * AesBytesEncryptor(
 * String password,
 * CharSequence salt,
 * BytesKeyGenerator ivGenerator,
 * AesBytesEncryptor.CipherAlgorithm algorithm
 * )
 * <p>
 * This version introduces a **configurable cipher algorithm**.
 * <p>
 * In this demo we use:
 * <p>
 * AES-GCM (Galois Counter Mode)
 * <p>
 * AES-GCM is considered the modern standard for symmetric encryption because
 * it provides **Authenticated Encryption with Associated Data (AEAD)**.
 * <p>
 * -------------------------------------------------------------------------
 * ENCRYPTION PIPELINE
 * -------------------------------------------------------------------------
 * <p>
 * Password
 * │
 * ▼
 * PBKDF2 Key Derivation
 * │
 * ▼
 * AES Secret Key
 * │
 * ▼
 * Initialization Vector (IV)
 * │
 * ▼
 * AES-GCM Encryption
 * │
 * ▼
 * Ciphertext + Authentication Tag
 * <p>
 * -------------------------------------------------------------------------
 * WHAT IS AES-GCM?
 * -------------------------------------------------------------------------
 * <p>
 * GCM = Galois Counter Mode
 * <p>
 * It provides both:
 * <p>
 * • Confidentiality (encryption)
 * • Integrity (authentication)
 * <p>
 * Unlike CBC mode, AES-GCM automatically detects:
 * <p>
 * • Tampered ciphertext
 * • Modified data
 * • Incorrect encryption key
 * <p>
 * If any corruption occurs, decryption fails.
 * <p>
 * -------------------------------------------------------------------------
 * SECURITY BENEFITS OF GCM
 * -------------------------------------------------------------------------
 * <p>
 * • Authenticated encryption
 * • Built-in integrity verification
 * • Faster than CBC on modern CPUs
 * • Widely used in TLS, HTTPS, VPNs
 * <p>
 * -------------------------------------------------------------------------
 * IMPORTANT NOTE
 * -------------------------------------------------------------------------
 * <p>
 * AES encryption is reversible.
 * This differs from password hashing algorithms like Argon2.
 */

public class AES_Bytes_Encryption_Demo_V3 {

    private static final Logger logger = Logger.getLogger(AES_Bytes_Encryption_Demo_V3.class.getName());

    public static void main(String[] args) {

        logger.info("=========== AES-GCM ENCRYPTION DEMO V3 STARTED ===========");
        try {
            //------------------------------------------------------------------
            // STEP 1: DEFINE PASSWORD AND GENERATE SALT
            //------------------------------------------------------------------
            // Spring Security derives the AES key using: password + salt
            // via PBKDF2 key derivation.
            // Salt ensures:
            // • stronger randomness
            // • protection against rainbow-table attacks

            String password = "SecurePassword2026";
            Objects.requireNonNull(password, "Encryption password cannot be null.");
            String salt = KeyGenerators.string().generateKey();
            logger.info("Password defined successfully.");
            logger.info("Generated salt: " + salt);

            //------------------------------------------------------------------
            // STEP 2: INITIALIZATION VECTOR GENERATOR
            //------------------------------------------------------------------
            // AES block size = 16 bytes
            // The IV generator produces cryptographically secure
            // random IV values required for encryption.

            BytesKeyGenerator ivGenerator = KeyGenerators.secureRandom(16);
            logger.info("Secure IV generator initialized.");

            //------------------------------------------------------------------
            // STEP 3: INITIALIZE AES ENCRYPTOR WITH GCM ALGORITHM
            //------------------------------------------------------------------
            // Constructor used: AesBytesEncryptor(password, salt, ivGenerator, algorithm)
            // Algorithm selected: CipherAlgorithm.GCM
            // Internally Spring Security performs:
            // 1) PBKDF2 key derivation
            // 2) AES key generation
            // 3) IV creation
            // 4) AES-GCM encryption

            AesBytesEncryptor encryptor = new AesBytesEncryptor(password, salt, ivGenerator, AesBytesEncryptor.CipherAlgorithm.GCM);
            logger.info("AES encryptor initialized using GCM mode.");

            //------------------------------------------------------------------
            // STEP 4: PREPARE PLAINTEXT DATA
            //------------------------------------------------------------------

            String data = "AES Encryption using GCM Mode";
            Objects.requireNonNull(data, "Input data cannot be null.");
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext prepared for encryption.");
            logger.info("Plaintext length: " + plaintext.length + " bytes");

            //------------------------------------------------------------------
            // STEP 5: PERFORM ENCRYPTION
            //------------------------------------------------------------------
            // encrypt(byte[])
            // plaintext
            //     │
            //     ▼
            // AES-GCM encryption
            //     │
            //     ▼
            // ciphertext + authentication tag

            byte[] encrypted = encryptor.encrypt(plaintext);
            logger.info("Encryption completed successfully.");

            //------------------------------------------------------------------
            // STEP 6: DISPLAY ENCRYPTED OUTPUT
            //------------------------------------------------------------------

            String encodedCiphertext = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted Data (Base64): " + encodedCiphertext);
            logger.info("Ciphertext length: " + encrypted.length + " bytes");

            //------------------------------------------------------------------
            // STEP 7: PERFORM DECRYPTION
            //------------------------------------------------------------------
            // decrypt(byte[])
            // During decryption AES-GCM verifies
            // the authentication tag automatically.
            // If verification fails → decryption error.

            byte[] decrypted = encryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decryption completed successfully.");
            logger.info("Decrypted text: " + decryptedText);

            //------------------------------------------------------------------
            // STEP 8: VERIFY DATA INTEGRITY
            //------------------------------------------------------------------

            boolean integrityCheck = data.equals(decryptedText);
            if (integrityCheck) {
                logger.info("Integrity verification: SUCCESS");
            } else {
                logger.warning("Integrity verification: FAILED");
            }
            logger.info("=========== AES-GCM ENCRYPTION DEMO V3 COMPLETED ===========");
        }

        //------------------------------------------------------------------
        // EXCEPTION HANDLING
        //------------------------------------------------------------------

        catch (IllegalArgumentException ex) {
            logger.log(Level.SEVERE, "Invalid input supplied to encryption process.", ex);
        } catch (IllegalStateException ex) {
            logger.log(Level.SEVERE, "Encryption or decryption operation failed. "
                    + "Possible causes include incorrect password, "
                    + "invalid salt, corrupted ciphertext, "
                    + "or authentication tag mismatch.", ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Unexpected system error occurred.", ex);
        }
    }
}
