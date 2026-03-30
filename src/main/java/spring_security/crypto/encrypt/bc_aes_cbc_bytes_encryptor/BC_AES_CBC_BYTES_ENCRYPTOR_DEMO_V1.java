package spring_security.crypto.encrypt.bc_aes_cbc_bytes_encryptor;

import org.springframework.security.crypto.encrypt.BouncyCastleAesCbcBytesEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * BOUNCY_CASTLE_AES_CBC_BYTES_ENCRYPTOR_DEMO_V1
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates usage of: BouncyCastleAesCbcBytesEncryptor(String password, CharSequence salt)
 * ==========================================================================================
 * CORE CONCEPT: PASSWORD-BASED ENCRYPTION (PBE)
 * ==========================================================================================
 * Instead of raw keys:
 * password + salt → Key Derivation Function → AES Key
 * This means:
 * ✔ No key storage needed
 * ✔ Same inputs → same encryption capability
 * ==========================================================================================
 * WHY TWO INSTANCES?
 * ==========================================================================================
 * This encryptor is STATELESS.
 * It does NOT store:
 * • encryption state
 * • session key
 * So:
 * ✔ Encryption instance → used to encrypt
 * ✔ Decryption instance → recreated independently
 * REQUIREMENT:
 * SAME password + SAME salt
 * ==========================================================================================
 * INTERNAL FLOW
 * ==========================================================================================
 * ENCRYPTION:
 * 1) Derive AES key from (password + salt)
 * 2) Generate random IV
 * 3) AES/CBC encrypt data
 * 4) Prepend IV to ciphertext
 * DECRYPTION:
 * 1) Extract IV from ciphertext
 * 2) Derive same AES key
 * 3) Decrypt using AES/CBC
 * ==========================================================================================
 * SECURITY NOTES
 * ==========================================================================================
 * ✔ Use strong password
 * ✔ Use random salt (SecureRandom in production)
 * ❌ CBC does NOT detect tampering
 * → attacker can modify ciphertext without detection
 */
public class BC_AES_CBC_BYTES_ENCRYPTOR_DEMO_V1 {

    private static final Logger logger = Logger.getLogger(BC_AES_CBC_BYTES_ENCRYPTOR_DEMO_V1.class.getName());

    public static void main(String[] args) {

        logger.info("========== AES CBC BOUNCY CASTLE DEMO V1 STARTED ==========");
        try {

            // ==================================================================================
            // STEP 1: DEFINE PASSWORD & SALT
            // ==================================================================================
            // These act as the "root secret" for key derivation
            // IMPORTANT:
            //   • Must be SAME for encryption & decryption
            //   • In production → salt should be RANDOM per use case
            String password = "StrongPassword@123";
            String salt = KeyGenerators.string().generateKey(); // We are generating production-ready salt here

            logger.info("Password and salt defined.");

            // ==================================================================================
            // STEP 2: CREATE ENCRYPTOR INSTANCE (FOR ENCRYPTION)
            // ==================================================================================
            BouncyCastleAesCbcBytesEncryptor encryptor = new BouncyCastleAesCbcBytesEncryptor(password, salt);

            logger.info("Encryption instance created.");

            // ==================================================================================
            // STEP 3: PREPARE DATA
            // ==================================================================================
            String data = "Bouncy Castle AES CBC Demo V1";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);

            // ==================================================================================
            // STEP 4: ENCRYPT
            // ==================================================================================
            byte[] encrypted = encryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            // ==================================================================================
            // STEP 5: CREATE NEW INSTANCE (FOR DECRYPTION)
            // ==================================================================================
            // Simulates:
            //   • Another service
            //   • Another JVM
            //   • Another time
            BouncyCastleAesCbcBytesEncryptor decryptor = new BouncyCastleAesCbcBytesEncryptor(password, salt);
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
            logger.info("Integrity Check (logical): " + isMatch);
            if (!isMatch) {
                logger.warning("Data mismatch detected!");
            }
            logger.info("========== AES CBC DEMO V1 COMPLETED ==========");
        } catch (Exception ex) {
            // ==================================================================================
            // ERROR HANDLING
            // ==================================================================================
            // Possible Issues:
            // • Wrong password/salt → decryption fails or garbage output
            // • Corrupted ciphertext → partial/incorrect output
            // NOTE:
            // CBC does NOT guarantee integrity → no explicit tamper exception
            logger.log(Level.SEVERE, "Error in AES CBC Bouncy Castle demo V1", ex);
        }
    }
}
