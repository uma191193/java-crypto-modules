package spring_security.crypto.encrypt;

import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_SECRET_Encryption_KeyObjects_Demo_V3
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaSecretEncryptor(String encoding,PublicKey publicKey,PrivateKey privateKey)
 * ------------------------------------------------------------------
 * CORE CONCEPT: HYBRID ENCRYPTION
 * ------------------------------------------------------------------
 * Internally:
 * 1) Generate random AES key
 * 2) Encrypt plaintext using AES
 * 3) Encrypt AES key using RSA (Public Key)
 * 4) Combine → final ciphertext
 * ------------------------------------------------------------------
 * KEY BEHAVIOR
 * ------------------------------------------------------------------
 * ✔ PublicKey  → Encryption
 * ✔ PrivateKey → Decryption (optional but required for full cycle)
 * ------------------------------------------------------------------
 * ADVANTAGE OVER PEM VERSION
 * ------------------------------------------------------------------
 * ✔ No PEM parsing issues
 * ✔ Strong typing (Key objects)
 * ✔ Ideal for enterprise usage
 */
public class RSA_SECRET_Encryption_KeyObjects_Demo_V3 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_KeyObjects_Demo_V3.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA SECRET KEY OBJECTS DEMO V3 STARTED ==========");
        try {
            //----------------------------------------------------------
            // STEP 1: GENERATE RSA KEY PAIR
            //----------------------------------------------------------
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            logger.info("RSA KeyPair generated (2048-bit).");

            //----------------------------------------------------------
            // STEP 2: INITIALIZE ENCRYPTOR
            //----------------------------------------------------------
            // encoding = UTF-8 (controls string <-> byte conversion)
            RsaSecretEncryptor rsaSecretEncryptor = new RsaSecretEncryptor("UTF-8", keyPair.getPublic(), keyPair.getPrivate());
            logger.info("Encryptor initialized with Public + Private keys.");

            //----------------------------------------------------------
            // STEP 3: PREPARE DATA
            //----------------------------------------------------------
            String data = "RSA Secret Encryptor V3 Demo (Key Objects)";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);

            //----------------------------------------------------------
            // STEP 4: ENCRYPT
            //----------------------------------------------------------
            byte[] encrypted = rsaSecretEncryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            //----------------------------------------------------------
            // STEP 5: DECRYPT
            //----------------------------------------------------------
            byte[] decrypted = rsaSecretEncryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted: " + decryptedText);

            //----------------------------------------------------------
            // STEP 6: VERIFY
            //----------------------------------------------------------
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check: " + isMatch);
            if (!isMatch) {
                logger.warning("Data mismatch detected!");
            }
            logger.info("========== RSA SECRET DEMO V3 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            logger.log(Level.SEVERE, "Error in RSA Secret Encryptor V3 demo", ex);
        }
    }
}