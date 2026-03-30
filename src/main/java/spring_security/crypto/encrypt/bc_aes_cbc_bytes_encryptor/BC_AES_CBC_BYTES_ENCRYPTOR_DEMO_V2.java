package spring_security.crypto.encrypt.bc_aes_cbc_bytes_encryptor;

import org.springframework.security.crypto.encrypt.BouncyCastleAesCbcBytesEncryptor;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * BC_AES_CBC_BYTES_ENCRYPTOR_DEMO_V2
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of:BouncyCastleAesCbcBytesEncryptor(String password, CharSequence salt, BytesKeyGenerator ivGenerator)
 * ==========================================================================================
 * WHAT IS NEW IN V2?
 * ==========================================================================================
 * ✔ Developer controls IV generation
 * ✔ Can enforce RANDOM or FIXED IV strategies
 * ==========================================================================================
 * IV (Initialization Vector) ROLE
 * ==========================================================================================
 * IV ensures that:
 * Same plaintext → produces DIFFERENT ciphertext each time
 * Without IV randomness:
 * ❌ Patterns leak
 * ❌ Vulnerable to replay & analysis attacks
 * ==========================================================================================
 * IV STRATEGIES
 * ==========================================================================================
 * 1) RANDOM IV  (Recommended)
 * → KeyGenerators.secureRandom(16)
 * 2) FIXED IV (Demo only - insecure)
 * → KeyGenerators.shared(16)
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * ENCRYPTION:
 * 1) Derive AES key (password + salt)
 * 2) Generate IV using ivGenerator
 * 3) AES/CBC encrypt
 * 4) Prepend IV to ciphertext
 * DECRYPTION:
 * 1) Extract IV
 * 2) Derive same AES key
 * 3) Decrypt
 * ==========================================================================================
 * SECURITY NOTES
 * ==========================================================================================
 * ✔ Always use RANDOM IV in production
 * ❌ CBC has NO integrity protection
 */
public class BC_AES_CBC_BYTES_ENCRYPTOR_DEMO_V2 {

    private static final Logger logger = Logger.getLogger(BC_AES_CBC_BYTES_ENCRYPTOR_DEMO_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== BC AES CBC BYTES ENCRYPTOR DEMO V2 STARTED ==========");
        try {
            // ==================================================================================
            // STEP 1: PASSWORD & SALT
            // ==================================================================================
            String password = "StrongPassword@123";
            String salt = KeyGenerators.string().generateKey(); // We are generating production-ready salt here

            logger.info("Password and salt defined.");
            // ==================================================================================
            // STEP 2: DEFINE IV GENERATOR
            // ==================================================================================
            // SECURE OPTION:
            // Generates cryptographically strong random IV (16 bytes for AES)
            BytesKeyGenerator ivGenerator = KeyGenerators.secureRandom(16);

            // INSECURE OPTION (for learning only):
            // BytesKeyGenerator ivGenerator = KeyGenerators.shared(16);

            logger.info("IV Generator configured (secureRandom).");
            // ==================================================================================
            // STEP 3: CREATE ENCRYPTOR (ENCRYPTION INSTANCE)
            // ==================================================================================
            BouncyCastleAesCbcBytesEncryptor encryptor = new BouncyCastleAesCbcBytesEncryptor(password, salt, ivGenerator);
            logger.info("Encryption instance created.");

            // ==================================================================================
            // STEP 4: PREPARE DATA
            // ==================================================================================
            String data = "BC AES CBC Demo V2 - Custom IV Generator";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);

            // ==================================================================================
            // STEP 5: ENCRYPT
            // ==================================================================================
            byte[] encrypted = encryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            // ==================================================================================
            // STEP 6: CREATE NEW INSTANCE (DECRYPTION)
            // ==================================================================================
            // IMPORTANT:
            // Same password + salt required
            // IV generator should be SAME TYPE (especially if fixed)
            //
            BouncyCastleAesCbcBytesEncryptor decryptor = new BouncyCastleAesCbcBytesEncryptor(password, salt, ivGenerator);
            logger.info("Decryption instance recreated.");

            // ==================================================================================
            // STEP 7: DECRYPT
            // ==================================================================================
            byte[] decrypted = decryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted: " + decryptedText);

            // ==================================================================================
            // STEP 8: VERIFY
            // ==================================================================================
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check (logical): " + isMatch);
            if (!isMatch) {
                logger.warning("Data mismatch detected!");
            }
            logger.info("========== BC AES CBC DEMO V2 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            // Possible Issues:
            // • Wrong password/salt → incorrect decryption
            // • IV mismatch (fixed generator misuse)
            // • Corrupted ciphertext
            logger.log(Level.SEVERE, "Error in BC AES CBC Bytes Encryptor Demo V2", ex);
        }
    }
}