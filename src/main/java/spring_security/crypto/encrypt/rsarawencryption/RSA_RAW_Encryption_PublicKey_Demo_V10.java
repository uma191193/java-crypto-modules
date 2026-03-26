package spring_security.crypto.encrypt.rsarawencryption;

import org.springframework.security.crypto.encrypt.RsaRawEncryptor;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_RAW_Encryption_PublicKey_Demo_V10
 * ------------------------------------------------------------------
 * PURPOSE:
 * Demonstrates usage of: RsaRawEncryptor(PublicKey publicKey)
 * ------------------------------------------------------------------
 * CORE IDEA
 * ------------------------------------------------------------------
 * This constructor enables:
 * ✔ Encryption using ONLY public key
 * ❌ Decryption is NOT possible (no private key)
 * ------------------------------------------------------------------
 * REAL-WORLD USAGE
 * ------------------------------------------------------------------
 * ✔ Client encrypts data using server's public key
 * ✔ Only server (with private key) can decrypt
 * Examples:
 * • HTTPS handshake (conceptually)
 * • Secure API payloads
 * • Public key encryption systems
 * ------------------------------------------------------------------
 * INTERNAL BEHAVIOR
 * ------------------------------------------------------------------
 * Uses default RSA transformation:
 * → RSA/ECB/PKCS1Padding (legacy)
 * ------------------------------------------------------------------
 * IMPORTANT LIMITATION
 * ------------------------------------------------------------------
 * Calling decrypt() will throw exception:
 * → because PrivateKey is not available
 */
public class RSA_RAW_Encryption_PublicKey_Demo_V10 {

    private static final Logger logger = Logger.getLogger(RSA_RAW_Encryption_PublicKey_Demo_V10.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA PUBLIC KEY DEMO V10 STARTED ==========");

        try {
            //----------------------------------------------------------
            // STEP 1: GENERATE RSA KEY PAIR (SIMULATION)
            //----------------------------------------------------------
            // In real-world:
            // • Sender only has PublicKey
            // • Receiver holds PrivateKey
            // Here we generate both just for demonstration

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            logger.info("Public Key generated.");
            //----------------------------------------------------------
            // STEP 2: INITIALIZE ENCRYPTOR WITH PUBLIC KEY ONLY
            //----------------------------------------------------------
            RsaRawEncryptor encryptor = new RsaRawEncryptor(publicKey);
            logger.info("Encryptor initialized with PublicKey ONLY.");
            //----------------------------------------------------------
            // STEP 3: PREPARE DATA
            //----------------------------------------------------------
            String data = "Public Key Encryption Demo V10";
            Objects.requireNonNull(data);
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);
            //----------------------------------------------------------
            // STEP 4: ENCRYPT
            //----------------------------------------------------------
            byte[] encrypted = encryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);
            //----------------------------------------------------------
            // STEP 5: DECRYPT (SIMULATED RECEIVER SIDE)
            //----------------------------------------------------------
            // IMPORTANT: RsaRawEncryptor (this instance) CANNOT decrypt
            // So we simulate receiver using full key pair

            RsaRawEncryptor rsaRawEncryptor = new RsaRawEncryptor(keyPair); // has private key
            byte[] decrypted = rsaRawEncryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted (Receiver Side): " + decryptedText);
            //----------------------------------------------------------
            // STEP 6: VERIFY
            //----------------------------------------------------------
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check: " + isMatch);
            if (!isMatch) {
                logger.warning("Data mismatch detected!");
            }
            //----------------------------------------------------------
            // IMPORTANT WARNING DEMO
            //----------------------------------------------------------
            // Uncommenting below will FAIL:
            // encryptor.decrypt(encrypted);
            // Reason: ❌ No PrivateKey → Cannot decrypt
            logger.info("========== RSA PUBLIC KEY DEMO V10 COMPLETED ==========");
        } catch (Exception ex) {
            //----------------------------------------------------------
            // ERROR HANDLING
            //----------------------------------------------------------
            // Possible failures:
            //
            // • InvalidKeyException
            // • IllegalBlockSizeException (data too large)
            // • BadPaddingException
            //----------------------------------------------------------
            logger.log(Level.SEVERE, "Error in PublicKey Demo V10", ex);
        }
    }
}