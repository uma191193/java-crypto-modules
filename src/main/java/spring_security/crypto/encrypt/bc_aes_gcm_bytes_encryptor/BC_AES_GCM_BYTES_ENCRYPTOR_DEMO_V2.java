package spring_security.crypto.encrypt.bc_aes_gcm_bytes_encryptor;

import org.springframework.security.crypto.encrypt.BouncyCastleAesGcmBytesEncryptor;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * BC_AES_GCM_BYTES_ENCRYPTOR_DEMO_V2
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: BouncyCastleAesGcmBytesEncryptor(String password, CharSequence salt, BytesKeyGenerator ivGenerator)
 * ==========================================================================================
 * WHAT IS NEW IN V2?
 * ==========================================================================================
 * ✔ Explicit IV (nonce) control
 * ✔ Enforces correct IV strategy for GCM
 * ==========================================================================================
 * CORE CONCEPT: GCM NONCE REQUIREMENT
 * ==========================================================================================
 * GCM requires:
 * ✔ Unique IV per encryption
 * If violated:
 * ❌ Key leakage risk
 * ❌ Ciphertext compromise
 * ==========================================================================================
 * SALT RULES (STRICT)
 * ==========================================================================================
 * ✔ Must be HEX
 * ✔ Must be even length
 * ✔ Only [0-9, a-f]
 * ==========================================================================================
 * IV STRATEGY
 * ==========================================================================================
 * ✔ secureRandom(12) → Recommended (GCM standard)
 * WHY 12 BYTES?
 * • Standard nonce size for GCM
 * • Optimized by cryptographic providers
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * ENCRYPTION:
 * 1) Derive AES key (password + salt)
 * 2) Generate IV using ivGenerator
 * 3) AES/GCM encrypt:
 * • Ciphertext
 * • Authentication Tag
 * 4) Output = IV + Ciphertext + Tag
 * DECRYPTION:
 * 1) Extract IV
 * 2) Derive same key
 * 3) Validate authentication tag
 * 4) If valid → decrypt
 * If tampered → exception
 * ==========================================================================================
 * SECURITY NOTES
 * ==========================================================================================
 * ✔ ALWAYS use secureRandom IV
 * ❌ NEVER reuse IV
 * ✔ Use strong password
 */
public class BC_AES_GCM_BYTES_ENCRYPTOR_DEMO_V2 {

    private static final Logger logger = Logger.getLogger(BC_AES_GCM_BYTES_ENCRYPTOR_DEMO_V2.class.getName());

    public static void main(String[] args) {

        logger.info("========== BC AES GCM BYTES ENCRYPTOR DEMO V2 STARTED ==========");
        try {

            // ==================================================================================
            // STEP 1: PASSWORD & SALT (STRICT HEX)
            // ==================================================================================
            String password = "StrongPassword@123";
            String salt = KeyGenerators.string().generateKey(); // We are generating production-ready salt here
            logger.info("Password and HEX salt defined.");

            // ==================================================================================
            // STEP 2: IV GENERATOR (CRITICAL FOR GCM)
            // ==================================================================================
            // MUST be secureRandom for GCM
            BytesKeyGenerator ivGenerator = KeyGenerators.secureRandom(16);
            logger.info("IV Generator configured (secureRandom, 12 bytes).");

            // ==================================================================================
            // STEP 3: CREATE ENCRYPTION INSTANCE
            // ==================================================================================
            BouncyCastleAesGcmBytesEncryptor encryptor = new BouncyCastleAesGcmBytesEncryptor(password, salt, ivGenerator);
            logger.info("Encryption instance created.");

            // ==================================================================================
            // STEP 4: PREPARE DATA
            // ==================================================================================
            String data = "BC AES GCM Demo V2 - Custom IV Generator";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);

            // ==================================================================================
            // STEP 5: ENCRYPT
            // ==================================================================================
            byte[] encrypted = encryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            // ==================================================================================
            // STEP 6: CREATE DECRYPTION INSTANCE
            // ==================================================================================
            // Same password + salt required
            // IV is extracted from ciphertext → generator consistency still recommended
            BouncyCastleAesGcmBytesEncryptor decryptor = new BouncyCastleAesGcmBytesEncryptor(password, salt, ivGenerator);
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
            logger.info("Integrity Check: " + isMatch);
            if (!isMatch) {
                logger.warning("Data mismatch detected!");
            }
            logger.info("========== BC AES GCM DEMO V2 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            //
            // Common failures:
            //
            // • AEADBadTagException → tampering detected
            // • IllegalArgumentException → invalid HEX salt
            // • Wrong password/salt → authentication failure
            //
            logger.log(Level.SEVERE, "Error in BC AES GCM Bytes Encryptor Demo V2", ex);
        }
    }
}