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
 * AES_Bytes_Encryption_Demo_V5
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
 * AES-CBC (Cipher Block Chaining Mode)
 * <p>
 * AES-CBC is a traditional symmetric encryption mode that provides
 * confidentiality but does not include built-in integrity verification.
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
 * AES-CBC Encryption
 * │
 * ▼
 * Ciphertext
 * <p>
 * -------------------------------------------------------------------------
 * WHAT IS AES-CBC?
 * -------------------------------------------------------------------------
 * <p>
 * CBC = Cipher Block Chaining
 * <p>
 * Each plaintext block is XORed with the previous ciphertext block
 * before encryption.
 * <p>
 * This ensures identical plaintext blocks produce different ciphertext
 * outputs depending on previous encryption results.
 * <p>
 * However CBC mode does NOT provide built-in authentication.
 * <p>
 * -------------------------------------------------------------------------
 * SECURITY CHARACTERISTICS OF CBC
 * -------------------------------------------------------------------------
 * <p>
 * • Provides confidentiality (encryption)
 * • Requires a random Initialization Vector (IV)
 * • Does NOT automatically detect tampering
 * <p>
 * For modern applications AES-GCM is generally preferred.
 * <p>
 * -------------------------------------------------------------------------
 * IMPORTANT NOTE
 * -------------------------------------------------------------------------
 * <p>
 * AES encryption is reversible.
 * This differs from password hashing algorithms like Argon2.
 */

public class AES_Bytes_Encryption_Demo_V5 {

    private static final Logger logger = Logger.getLogger(AES_Bytes_Encryption_Demo_V5.class.getName());

    public static void main(String[] args) {

        logger.info("=========== AES-CBC ENCRYPTION DEMO V5 STARTED ===========");
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
            // The IV generator produces cryptographically secure random IV values required for encryption.

            BytesKeyGenerator ivGenerator = KeyGenerators.secureRandom(16);
            logger.info("Secure IV generator initialized.");

            //------------------------------------------------------------------
            // STEP 3: INITIALIZE AES ENCRYPTOR WITH CBC ALGORITHM
            //------------------------------------------------------------------
            // Constructor used: AesBytesEncryptor(password, salt, ivGenerator, algorithm)
            // Algorithm selected: CipherAlgorithm.CBC
            // Internally Spring Security performs:
            // 1) PBKDF2 key derivation
            // 2) AES key generation
            // 3) IV creation
            // 4) AES-CBC encryption

            AesBytesEncryptor encryptor = new AesBytesEncryptor(password, salt, ivGenerator, AesBytesEncryptor.CipherAlgorithm.CBC);
            logger.info("AES encryptor initialized using CBC mode.");

            //------------------------------------------------------------------
            // STEP 4: PREPARE PLAINTEXT DATA
            //------------------------------------------------------------------

            String data = "AES Encryption using CBC Mode";
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
            // AES-CBC encryption
            //     │
            //     ▼
            // ciphertext

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
            logger.info("=========== AES-CBC ENCRYPTION DEMO V5 COMPLETED ===========");
        }

        //------------------------------------------------------------------
        // EXCEPTION HANDLING
        //------------------------------------------------------------------

        catch (IllegalArgumentException ex) {
            logger.log(Level.SEVERE, "Invalid input supplied to encryption process.", ex);
        } catch (IllegalStateException ex) {
            logger.log(Level.SEVERE, "Encryption or decryption operation failed. "
                    + "Possible causes include incorrect password, "
                    + "invalid salt or corrupted ciphertext.", ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Unexpected system error occurred.", ex);
        }
    }
}