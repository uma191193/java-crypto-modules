package spring_security.crypto.encrypt.rsasecretencryption;

import org.springframework.security.crypto.encrypt.RsaAlgorithm;
import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RSA_SECRET_Encryption_AlgorithmOnly_Demo_V12
 * ==========================================================================================
 * PURPOSE
 * ==========================================================================================
 * Demonstrates:
 * RsaSecretEncryptor(RsaAlgorithm algorithm)
 * ==========================================================================================
 * CORE IDEA
 * ==========================================================================================
 * This constructor provides:
 * ✔ Control over RSA padding algorithm
 * ✔ Fully INTERNAL key management
 * BUT:
 * ❌ No external KeyPair provided
 * ❌ No PublicKey / PrivateKey control
 * ==========================================================================================
 * WHAT DOES THIS MEAN?
 * ==========================================================================================
 * Internally:
 * • A KeyPair is generated or managed within the encryptor
 * • AES key is generated per encryption
 * • Hybrid encryption is still used
 * HOWEVER:
 * This instance is SELF-CONTAINED
 * ==========================================================================================
 * IMPORTANT LIMITATION
 * ==========================================================================================
 * ✔ Encryption works
 * ✔ Decryption works ONLY with SAME INSTANCE
 * ❌ Cannot share ciphertext across systems
 * ==========================================================================================
 * USE CASE
 * ==========================================================================================
 * ✔ Internal application encryption
 * ✔ Temporary data protection
 * ✔ Not suitable for distributed systems
 * ==========================================================================================
 * ALGORITHM DETAILS
 * ==========================================================================================
 * Using:
 * RsaAlgorithm.OAEP
 * Maps to:
 * RSA/ECB/OAEPWithSHA-1AndMGF1Padding
 * ==========================================================================================
 * SECURITY MODEL
 * ==========================================================================================
 * ✔ Hybrid encryption (RSA + AES)
 * ✔ Secure padding (OAEP)
 * BUT:
 * ✔ No external key control → limited flexibility
 */
public class RSA_SECRET_Encryption_AlgorithmOnly_Demo_V12 {

    private static final Logger logger = Logger.getLogger(RSA_SECRET_Encryption_AlgorithmOnly_Demo_V12.class.getName());

    public static void main(String[] args) {

        logger.info("========== RSA ALGORITHM-ONLY DEMO V12 STARTED ==========");

        try {

            // ==================================================================================
            // STEP 1: SELECT RSA ALGORITHM
            // ==================================================================================
            // OAEP → RSA/ECB/OAEPWithSHA-1AndMGF1Padding
            // Provides:
            //   • Randomized padding
            //   • Protection against padding attacks
            RsaAlgorithm algorithm = RsaAlgorithm.OAEP;
            logger.info("Algorithm selected: " + algorithm);

            // ==================================================================================
            // STEP 2: INITIALIZE ENCRYPTOR (NO KEYS PROVIDED)
            // ==================================================================================
            // Internally handles:
            //   • RSA KeyPair generation/management
            //   • AES key lifecycle
            //
            RsaSecretEncryptor rsaSecretEncryptor = new RsaSecretEncryptor(algorithm);
            logger.info("Encryptor initialized (Algorithm-only mode).");

            // ==================================================================================
            // STEP 3: PREPARE DATA
            // ==================================================================================
            String data = "RSA Algorithm Only Demo (V12)";
            byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
            logger.info("Plaintext: " + data);

            // ==================================================================================
            // STEP 4: ENCRYPT
            // ==================================================================================
            // INTERNAL FLOW:
            //   1) Generate AES key
            //   2) AES encrypt data
            //   3) RSA encrypt AES key (OAEP)
            byte[] encrypted = rsaSecretEncryptor.encrypt(plaintext);
            String base64Cipher = Base64.getEncoder().encodeToString(encrypted);
            logger.info("Encrypted (Base64): " + base64Cipher);

            // ==================================================================================
            // STEP 5: DECRYPT (SAME INSTANCE ONLY)
            // ==================================================================================
            // IMPORTANT:
            //   This works ONLY because same encryptor instance
            //   holds the required internal key material
            byte[] decrypted = rsaSecretEncryptor.decrypt(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            logger.info("Decrypted: " + decryptedText);

            // ==================================================================================
            // STEP 6: VERIFY
            // ==================================================================================
            boolean isMatch = data.equals(decryptedText);
            logger.info("Integrity Check: " + isMatch);
            logger.info("========== RSA ALGORITHM-ONLY DEMO V12 COMPLETED ==========");
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Error in RSA Algorithm-only Demo V12", ex);
        }
    }
}