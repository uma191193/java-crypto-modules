package jdk_24;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Demonstration of Post-Quantum Digital Signatures in Java 24 using ML-DSA,
 * enhanced with detailed comments, exception handling, and java.util.logging.
 * Concepts:
 * - ML-DSA (Module-Lattice Digital Signature Algorithm) → PQC (Post-Quantum Cryptography)
 * algorithm standardized by NIST (based on CRYSTALS-Dilithium).
 * - Designed to resist quantum attacks (unlike RSA/ECDSA).
 * In Java 24:
 * - KeyPairGenerator → generate new PQ keypairs.
 * - KeyFactory → rebuild keys from stored/transmitted form (PKCS#8 / X.509).
 * - Signature → sign and verify messages with digital signatures.
 * Note: ML-DSA signatures are larger (2–5 KB) compared to RSA/ECDSA,
 * but provide quantum resistance.
 */
public class ML_DSA_Signature_V2 {

    private static final Logger log = Logger.getLogger(ML_DSA_Signature_V2.class.getName());

    public static void main(String[] args) {

        try {
            /*
             * STEP 1: Generate a KeyPair
             * ---------------------------
             * A KeyPair = {PrivateKey, PublicKey}.
             *
             * - KeyPairGenerator is responsible for generating fresh cryptographic keys.
             * - Here we request ML-DSA with a specific parameter set:
             * "ML-DSA-44" → Level 1 (~128-bit security)
             * "ML-DSA-65" → Level 3 (~192-bit security) [DEFAULT]
             * "ML-DSA-87" → Level 5 (~256-bit security)
             *
             * Increasing levels → larger signatures, stronger security.
             */

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA-44");
            log.info("KeyPairGenerator initialized with algorithm: " + keyPairGenerator.getAlgorithm());
            log.info("Provider is : " + keyPairGenerator.getProvider());

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            log.info("KeyPair generated successfully.");

            /*
             * STEP 2: Prepare the input message
             * ----------------------------------
             * - We will sign a simple string message.
             * - In real-world use cases, signatures are applied to:
             * - Digital certificates
             * - Software executables (code signing)
             * - Secure communications (TLS handshake)
             *
             * Important: Signing does not encrypt the message.
             * It provides authenticity (who signed it) + integrity (unchanged data).
             */
            byte[] inputMessage = "hello, post-quantum Java 24 demo".getBytes(StandardCharsets.UTF_8);
            log.info("Input message prepared for signing.");

            /*
             * STEP 3: Create and initialize a Signature object for signing
             * ------------------------------------------------------------
             * - Signature is the JCA API for signing/verification.
             * - initSign(privateKey) loads the private key → only the owner can sign.
             * - update(inputMessage) streams the message into the signature engine.
             * - sign() performs:
             * 1. Hashing internally (SHAKE-256 as part of ML-DSA).
             * 2. Lattice-based signing process (Dilithium/ML-DSA math).
             * 3. Produces final signature bytes.
             */
            byte[] finalSignature = null;
            try {
                Signature signature = Signature.getInstance("ML-DSA-44");
                signature.initSign(keyPair.getPrivate());
                signature.update(inputMessage);
                finalSignature = signature.sign();
                log.info("Message signed successfully using ML-DSA-44.");
            } catch (GeneralSecurityException e) {
                log.log(Level.SEVERE, "Error during signing process", e);
                return; // exit since signing failed
            }

            /*
             * STEP 3a: KeyFactory (Key Reconstruction from Encoded Bytes)
             * -----------------------------------------------------------
             * Why KeyFactory?
             * - KeyPairGenerator → only for NEW keys.
             * - KeyFactory → rebuild keys from encoded form (PKCS#8 for private, X.509 for public).
             *
             * Real-world use case:
             * - Alice stores her private key in a PKCS#8 file.
             * - Bob receives Alice's public key inside an X.509 certificate.
             * - Applications load them back into usable Java objects via KeyFactory.
             */
            PublicKey rebuiltPublicKey = null;
            PrivateKey rebuiltPrivateKey = null;
            try {
                // Export original keys to encoded format
                byte[] encodedPublicKey = keyPair.getPublic().getEncoded();   // → X.509
                byte[] encodedPrivateKey = keyPair.getPrivate().getEncoded(); // → PKCS#8

                KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-44");

                // Rebuild the public key
                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encodedPublicKey);
                rebuiltPublicKey = keyFactory.generatePublic(pubSpec);

                // Rebuild the private key
                PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
                rebuiltPrivateKey = keyFactory.generatePrivate(privSpec);

                log.info("Keys successfully rebuilt using KeyFactory (from X.509 & PKCS#8 formats).");
            } catch (GeneralSecurityException e) {
                log.log(Level.SEVERE, "Error rebuilding keys with KeyFactory", e);
                return; // exit since keys could not be reconstructed
            }

            /*
             * STEP 4: Verify the signature
             * -----------------------------
             * - Verification requires ONLY the public key.
             * - Anyone can verify the signature, but only the private key holder
             * could have produced it.
             *
             * Here we deliberately use the rebuilt public key from KeyFactory
             * (instead of the original keyPair) to show that encoding/decoding works.
             *
             * Process:
             * - initVerify(publicKey) loads the verifier with public key.
             * - update(message) streams the original message.
             * - verify(signature) checks if signature matches the message & public key.
             */
            boolean verified = false;
            try {
                Signature verification = Signature.getInstance("ML-DSA-44");
                verification.initVerify(rebuiltPublicKey);
                verification.update(inputMessage);
                verified = verification.verify(finalSignature);
                log.info("Signature verification completed.");
            } catch (GeneralSecurityException e) {
                log.log(Level.SEVERE, "Error during signature verification", e);
                return; // exit since verification failed
            }

            /*
             * STEP 5: Print results
             * ----------------------
             * - ML-DSA signatures are larger than RSA/ECDSA:
             * ML-DSA-44 → ~2420 bytes
             * ML-DSA-65 → ~3309 bytes
             * ML-DSA-87 → ~4627 bytes
             *
             * - Large, but still practical for digital certificates, authentication, etc.
             */
            log.info("ML-DSA signature length: " + finalSignature.length + " bytes");
            log.info("Verify result (using KeyFactory public key): " + verified);
            log.fine("Signature (hex dump): " + HexFormat.of().formatHex(finalSignature));

        } catch (NoSuchAlgorithmException e) {
            log.log(Level.SEVERE, "Algorithm not available in this JDK provider", e);
        } catch (Exception e) {
            log.log(Level.SEVERE, "Unexpected runtime error occurred", e);
        }
    }
}