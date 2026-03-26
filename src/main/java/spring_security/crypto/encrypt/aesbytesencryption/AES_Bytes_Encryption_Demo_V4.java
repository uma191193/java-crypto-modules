package spring_security.crypto.encrypt.aesbytesencryption;

import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * AES_Bytes_Encryption_Demo_V4
 * -------------------------------------------------------------------------
 * This demo illustrates AES encryption using the most advanced constructor
 * of Spring Security's AesBytesEncryptor:
 * <p>
 * AesBytesEncryptor(
 * SecretKey secretKey,
 * BytesKeyGenerator ivGenerator,
 * AesBytesEncryptor.CipherAlgorithm algorithm
 * )
 * <p>
 * Unlike previous demos (V1–V3), this version does NOT derive the encryption
 * key from a password.
 * <p>
 * Instead, it uses a directly generated cryptographic AES key.
 * <p>
 * -------------------------------------------------------------------------
 * WHY USE SecretKey INSTEAD OF PASSWORDS?
 * -------------------------------------------------------------------------
 * <p>
 * Enterprise cryptographic systems usually do not derive keys from passwords.
 * <p>
 * Instead they rely on:
 * <p>
 * • Hardware Security Modules (HSM)
 * • Key Management Services (AWS KMS / Azure Key Vault)
 * • Secure key stores
 * • Cryptographic key rotation systems
 * <p>
 * These systems provide a **SecretKey** directly.
 * <p>
 * -------------------------------------------------------------------------
 * ENCRYPTION PIPELINE
 * -------------------------------------------------------------------------
 * <p>
 * AES SecretKey
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
 * AES-GCM SECURITY PROPERTIES
 * -------------------------------------------------------------------------
 * <p>
 * AES-GCM provides:
 * <p>
 * • Confidentiality (data encryption)
 * • Integrity (tamper detection)
 * • Authentication (ensures ciphertext not modified)
 * <p>
 * If ciphertext is altered, decryption fails automatically.
 * <p>
 * -------------------------------------------------------------------------
 * SECURITY NOTES
 * -------------------------------------------------------------------------
 * <p>
 * AES encryption is reversible.
 * The same key must be used for encryption and decryption.
 * <p>
 * Never expose encryption keys in source code in real systems.
 */

public class AES_Bytes_Encryption_Demo_V4 {

    private static final Logger logger = Logger.getLogger(AES_Bytes_Encryption_Demo_V4.class.getName());

    public static void main(String[] args) {

        logger.info("=========== AES SECRETKEY ENCRYPTION DEMO V4 STARTED ===========");
        try {
            //------------------------------------------------------------------
            // STEP 1: GENERATE AES SECRET KEY
            //------------------------------------------------------------------
            // Java Cryptography Architecture (JCA) provides a KeyGenerator that can produce secure AES keys.
            // AES supports key sizes:
            // 128-bit
            // 192-bit
            // 256-bit
            // We use AES-256 for stronger security.

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();
            Objects.requireNonNull(secretKey, "SecretKey generation failed.");
            logger.info("AES SecretKey generated successfully.");

            //------------------------------------------------------------------
            // STEP 2: INITIALIZATION VECTOR GENERATOR
            //------------------------------------------------------------------
            // AES block size = 16 bytes (128 bits)
            // Therefore IV length should be 16 bytes.

            BytesKeyGenerator ivGenerator = KeyGenerators.secureRandom(16);
            logger.info("Secure IV generator initialized.");

            //------------------------------------------------------------------
            // STEP 3: INITIALIZE AES ENCRYPTOR
            //------------------------------------------------------------------
            // Constructor used in this demo: AesBytesEncryptor(secretKey, ivGenerator, algorithm)
            // Algorithm selected: AES-GCM
            // Internal operations performed by Spring Security:
            // 1) AES cipher initialization
            // 2) IV generation
            // 3) AES-GCM encryption

            AesBytesEncryptor encryptor = new AesBytesEncryptor(secretKey, ivGenerator, AesBytesEncryptor.CipherAlgorithm.GCM);
            logger.info("AES encryptor initialized using SecretKey + GCM.");

            //------------------------------------------------------------------
            // STEP 4: PREPARE PLAINTEXT DATA
            //------------------------------------------------------------------

            String data = "AES Encryption using SecretKey";
            Objects.requireNonNull(data, "Input data cannot be null.");
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext prepared for encryption.");
            logger.info("Plaintext length: " + plaintext.length + " bytes");

            //------------------------------------------------------------------
            // STEP 5: PERFORM ENCRYPTION
            //------------------------------------------------------------------
            // encrypt(byte[])
            //
            // plaintext
            //      │
            //      ▼
            // AES-GCM encryption
            //      │
            //      ▼
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
            // AES-GCM verifies the authentication tag automatically.

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
            logger.info("=========== AES SECRETKEY ENCRYPTION DEMO V4 COMPLETED ===========");
        }

        //------------------------------------------------------------------
        // EXCEPTION HANDLING
        //------------------------------------------------------------------

        catch (IllegalArgumentException ex) {
            logger.log(Level.SEVERE, "Invalid input supplied to encryption process.", ex);
        } catch (IllegalStateException ex) {
            logger.log(Level.SEVERE, "Encryption/Decryption operation failed. "
                    + "Possible causes include corrupted ciphertext "
                    + "or authentication tag mismatch.", ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Unexpected system error occurred.", ex);
        }
    }
}
