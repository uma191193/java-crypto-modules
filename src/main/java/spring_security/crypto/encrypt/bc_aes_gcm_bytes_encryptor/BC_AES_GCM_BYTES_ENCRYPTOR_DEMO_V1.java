package spring_security.crypto.encrypt.bc_aes_gcm_bytes_encryptor;

import org.springframework.security.crypto.encrypt.BouncyCastleAesGcmBytesEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * BC_AES_GCM_BYTES_ENCRYPTOR_DEMO_V1
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: BouncyCastleAesGcmBytesEncryptor(String password, CharSequence salt)
 * ==========================================================================================
 * CORE CONCEPT: PASSWORD-BASED AUTHENTICATED ENCRYPTION (AEAD)
 * ==========================================================================================
 * password + salt → Key Derivation → AES Key
 * AES/GCM provides:
 * ✔ Confidentiality (encryption)
 * ✔ Integrity (authentication tag)
 * ==========================================================================================
 * WHY GCM OVER CBC?
 * ==========================================================================================
 * CBC:
 * ❌ No tamper detection
 * GCM:
 * ✔ Detects modification
 * ✔ Throws AEADBadTagException if tampered
 * ==========================================================================================
 * SALT RULES (STRICT)
 * ==========================================================================================
 * ✔ MUST be HEX string
 * ✔ MUST be even length
 * ✔ Only [0-9, a-f, A-F]
 * Example valid:
 * "a1b2c3d4e5f6a7b8"
 * ==========================================================================================
 * WHY TWO INSTANCES?
 * ==========================================================================================
 * Encryptor is STATELESS:
 * → Can recreate anywhere
 * REQUIREMENT:
 * SAME password + SAME salt
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * ENCRYPTION:
 * 1) Derive AES key (password + salt)
 * 2) Generate random IV (nonce)
 * 3) AES/GCM encrypt:
 * • Ciphertext
 * • Authentication Tag
 * 4) Output = IV + Ciphertext + Tag
 * DECRYPTION:
 * 1) Extract IV
 * 2) Derive same AES key
 * 3) Verify authentication tag
 * 4) If valid → decrypt
 * If tampered → EXCEPTION
 * ==========================================================================================
 * SECURITY NOTES
 * ==========================================================================================
 * ✔ Always use GCM in modern systems
 * ✔ Use strong password
 * ✔ Use random salt in production
 */
public class BC_AES_GCM_BYTES_ENCRYPTOR_DEMO_V1 {

    private static final Logger logger = Logger.getLogger(BC_AES_GCM_BYTES_ENCRYPTOR_DEMO_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== BC AES GCM BYTES ENCRYPTOR DEMO V1 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: PASSWORD & SALT (STRICT HEX)
            // ==================================================================================
            String password = "StrongPassword@123";
            String salt = KeyGenerators.string().generateKey(); // We are generating production-ready salt here
            logger.info("Password and HEX salt defined.");

            // ==================================================================================
            // STEP 2: CREATE ENCRYPTION INSTANCE
            // ==================================================================================
            BouncyCastleAesGcmBytesEncryptor encryptor = new BouncyCastleAesGcmBytesEncryptor(password, salt);
            logger.info("Encryption instance created.");

            // ==================================================================================
            // STEP 3: PREPARE DATA
            // ==================================================================================
            String data = "BC AES GCM Demo V1 - Authenticated Encryption";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);

            // ==================================================================================
            // STEP 4: ENCRYPT
            // ==================================================================================
            byte[] encrypted = encryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);

            logger.info("Encrypted (Base64): " + base64Cipher);

            // ==================================================================================
            // STEP 5: CREATE DECRYPTION INSTANCE
            // ==================================================================================
            BouncyCastleAesGcmBytesEncryptor decryptor = new BouncyCastleAesGcmBytesEncryptor(password, salt);
            logger.info("Decryption instance recreated.");

            // ==================================================================================
            // STEP 6: DECRYPT
            // ==================================================================================
            byte[] decrypted = decryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted: " + decryptedText);

            // ==================================================================================
            // STEP 7: VERIFY
            // ==================================================================================
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check: " + isMatch);
            if (!isMatch) {
                logger.warning("Data mismatch detected!");
            }
            logger.info("========== BC AES GCM DEMO V1 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            // Common failures:
            // • AEADBadTagException:
            //     → Ciphertext modified (tampering detected)
            // • IllegalArgumentException:
            //     → Invalid HEX salt
            // • Wrong password/salt:
            //     → Authentication failure
            logger.log(Level.SEVERE, "Error in BC AES GCM Bytes Encryptor Demo V1", ex);
        }
    }
}