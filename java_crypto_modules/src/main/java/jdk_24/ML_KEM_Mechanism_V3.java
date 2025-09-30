/*
package jdk_24;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.logging.Level;
import java.util.logging.Logger;

*/
/**
 * ML_KEM_Mechanism_V3
 * -------------------
 * This program demonstrates the **ML-KEM** algorithm family
 * (NIST FIPS 203: Module-Lattice-based Key Encapsulation Mechanism),
 * included in Java SE 24 via JEP 496 (Post-Quantum Cryptography).
 * Educational goals (expanded):
 * - Show how to request a PQC primitive using the *family name* (ML-KEM),
 * letting the JDK provider choose its default parameter set (e.g. ML-KEM-768).
 * - Show multiple ways to discover the *concrete* parameter set that was chosen:
 * * Directly from the Key object's AlgorithmParameterSpec (NamedParameterSpec).
 * * Indirectly via OID parsing (helper PQCParameterInspector_V2).
 * - Demonstrate exporting keys (SPKI / PKCS#8) and re-importing them via KeyFactory
 * to prove parameter sets survive serialization round-trips.
 * - Perform a KEM encapsulation/decapsulation to derive a shared symmetric key,
 * then use that key with AES/GCM to encrypt and decrypt a short message.
 * Important production notes (brief):
 * - This demo is educational. For production:
 * * Use secure key storage (HSM/keystore) instead of raw byte arrays.
 * * Zero sensitive material when possible (Arrays.fill on byte[]; destroy keys if possible).
 * * Consider authenticity and replay protections for capsules and IVs.
 *//*

public class ML_KEM_Mechanism_V3 {

    private static final Logger logger = Logger.getLogger(ML_KEM_Mechanism_V3.class.getName());

    public static void main(String[] args) {

        // ---------------------------------------------------------------------
        // STEP 0: Algorithm choice (family vs concrete)
        // ---------------------------------------------------------------------
        // We intentionally request only the algorithm *family* "ML-KEM".
        //
        // Rationale:
        //  - Providers expose families (like "ML-KEM") and may supply several
        //    concrete parameter sets (ML-KEM-512, -768, -1024).
        //  - Asking the family is convenient for demos and lets the provider pick
        //    a reasonable default (JDK 24 chooses ML-KEM-768).
        //  - If you have explicit security requirements (e.g., a policy mandating
        //    ML-KEM-1024), request that concrete name instead.
        //
        // Security classification:
        //  - ML-KEM-512, -768, -1024 correspond to different security levels
        //    (e.g., NIST categories). Choose according to your threat model.
        final String KEM_FAMILY = "ML-KEM";

        try {
            // -----------------------------------------------------------------
            // STEP 1: SecureRandom — why and which one
            // -----------------------------------------------------------------
            // Purpose:
            //   - Cryptographic operations (keygen, encapsulation) require high-quality randomness.
            //   - Using a weak RNG breaks security guarantees.
            //
            // getInstanceStrong() semantics:
            //   - Returns the strongest available RNG on the platform (may block on some OSes
            //     until enough entropy is available; on modern JVMs it maps to DRBG / non-blocking).
            //   - For deterministic tests you might inject a fixed SecureRandom, but never in production.
            //
            // Failure modes:
            //   - No strong algorithm available -> GeneralSecurityException; we catch and report below.
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();

            // -----------------------------------------------------------------
            // STEP 2: Alice generates her ML-KEM keypair (family-only request)
            // -----------------------------------------------------------------
            // What happens:
            //   - KeyPairGenerator.getInstance(KEM_FAMILY) asks the provider for an ML-KEM generator.
            //   - Without extra params, the provider chooses its default concrete variant.
            //   - keyPair contains a PublicKey and PrivateKey; the PublicKey carries AlgorithmParameterSpec
            //     which (for named parameter sets) is a NamedParameterSpec with the concrete name.
            //
            // Why we prefer the family request for demos:
            //   - Simulates client code that doesn't hardcode parameter sets.
            //   - Useful to determine provider defaults and interoperability behavior.
            //
            // Potential exceptions:
            //   - No provider implements ML-KEM -> NoSuchAlgorithmException.
            //   - Underlying platform error during generation -> GeneralSecurityException.
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEM_FAMILY);
            KeyPair aliceKeyPair = keyPairGenerator.generateKeyPair();

            logger.info("=== Key Information ===");
            logger.info("KeyPairGenerator algorithm : " + keyPairGenerator.getAlgorithm());
            logger.info("KeyPairGenerator Public key family : " + aliceKeyPair.getPublic().getAlgorithm());

            // (A) Directly inspect the parameter set embedded in the public key.
            //     This is the most authoritative source for which concrete set the key uses.
            AlgorithmParameterSpec params = ((AsymmetricKey) aliceKeyPair.getPublic()).getParams();
            if (params instanceof NamedParameterSpec named) {
                // Example output: "ML-KEM-768"
                logger.info("KeyPairGenerator Parameter set (NamedParameterSpec): " + named.getName());
            } else {
                // Not all implementations must expose a NamedParameterSpec; if not present,
                // we fall back to OID parsing or other provider-specific inspection.
                logger.warning("Public key parameters are not a NamedParameterSpec (cannot read concrete name directly).");
            }

            // (B) Indirect approach: inspect key encoding to find OID and map to name.
            //     Useful when NamedParameterSpec is not available or when you want a secondary check.
            //     PQCParameterInspector_V2 is a helper that you must provide; it parses encoded keys.
            try {
                String detected = PQCParameterInspector_V2.detectDefaultParam(KEM_FAMILY);
                // For example: "ML-KEM-768"
                logger.info("Parameter set (OID lookup) : " + detected);
            } catch (Exception e) {
                // OID parsing may fail if helper is missing or encoding is unexpected.
                logger.log(Level.WARNING, "OID parameter detection failed (helper missing or unparsable key)", e);
            }

            // -----------------------------------------------------------------
            // STEP 3: Export keys to standard encodings and re-import (round-trip)
            // -----------------------------------------------------------------
            // Why:
            //   - In real systems keys are stored/transmitted as bytes (SPKI/PKCS#8).
            //   - We must ensure that encoding and subsequent decoding preserve
            //     the algorithm parameters, otherwise interoperability breaks.
            //
            // Formats:
            //   - PublicKey.getEncoded() -> X.509 SubjectPublicKeyInfo (SPKI)
            //   - PrivateKey.getEncoded() -> PKCS#8 PrivateKeyInfo
            //
            // Potential pitfalls:
            //   - Different providers may encode parameters differently (but SPKI/PKCS#8 are standards).
            //   - Truncation/corruption of bytes will lead to parsing exceptions.
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(KEM_FAMILY);

                // Export to bytes
                byte[] x509Pub = aliceKeyPair.getPublic().getEncoded();
                byte[] pkcs8Pri = aliceKeyPair.getPrivate().getEncoded();

                // Re-import into fresh Key objects
                PublicKey alicePublicFromBytes = keyFactory.generatePublic(new X509EncodedKeySpec(x509Pub));
                PrivateKey alicePrivateFromBytes = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Pri));

                // Double-check: does the re-imported public key still report the same parameter set?
                AlgorithmParameterSpec rebuiltParams = ((AsymmetricKey) alicePublicFromBytes).getParams();
                if (rebuiltParams instanceof NamedParameterSpec named2) {
                    logger.info("KeyFactory rebuilt public param set (NamedParameterSpec) : " + named2.getName());
                } else {
                    logger.warning("Rebuilt public key does not expose NamedParameterSpec (cannot confirm concrete set).");
                }

                // -----------------------------------------------------------------
                // STEP 4: Bob encapsulates a shared secret to Alice's public key
                // -----------------------------------------------------------------
                // High-level idea:
                //   - Bob uses Alice's public key to encapsulate: produces a symmetric key (SecretKey)
                //     plus a capsule (byte[]). Only Alice can decapsulate the capsule with her private key
                //     to recover the same symmetric key.
                //
                // Practical notes on API usage:
                //   - KEM.getInstance(KEM_FAMILY) returns a provider-implemented KEM object.
                //   - kem.getAlgorithm() typically returns the string the provider registered.
                //   - encapsulator.encapsulate(0, 32, "AES"): here "0" is a context/label parameter
                //     (provider-specific — often unused), 32 requests 32 bytes (AES-256), "AES" is the
                //     algorithm name for the resulting SecretKey.
                //
                // Security considerations:
                //   - The randomness used during encapsulation must be high-quality (we pass our SecureRandom).
                //   - The capsule must be transmitted to Alice intact; tampering may cause decapsulation to fail.
                try {
                    KEM kem = KEM.getInstance(KEM_FAMILY);
                    logger.info("KEM instance algorithm : " + kem.getAlgorithm());

                    // Create an encapsulator bound to Alice's public key.
                    // The encapsulator object is provider-specific; printing its class is useful for debugging.
                    KEM.Encapsulator encapsulator = kem.newEncapsulator(alicePublicFromBytes, secureRandom);
                    logger.info("Encapsulator implementation: " + encapsulator.getClass().getName());

                    // Encapsulate: request a 32-byte symmetric key (AES-256).
                    // The returned KEM.Encapsulated contains both the key and the capsule.
                    KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");
                    SecretKey bobAes = encapsulated.key();            // Bob’s AES-256 key
                    byte[] kemMessage = encapsulated.encapsulation(); // Capsule to send to Alice

                    // Capsule byte-length varies by parameter set (implementation detail).
                    // Example (approx): ML-KEM-512 ~768B, ML-KEM-768 ~1088B, ML-KEM-1024 ~1568B
                    logger.info("Generated capsule length (bytes): " + kemMessage.length);

                    // -----------------------------------------------------------------
                    // STEP 5: Alice decapsulates the capsule using her private key
                    // -----------------------------------------------------------------
                    // High-level idea:
                    //   - Alice calls decapsulator.decapsulate(...) with the capsule and recovers a SecretKey
                    //     that should match Bob's derived SecretKey.
                    //   - If decapsulation fails (tampered capsule, wrong key), an exception may be thrown.
                    try {
                        KEM.Decapsulator decapsulator = kem.newDecapsulator(alicePrivateFromBytes);
                        logger.info("Decapsulator implementation: " + decapsulator.getClass().getName());

                        SecretKey aliceAes = decapsulator.decapsulate(kemMessage, 0, 32, "AES");

                        // At this point, both sides have a SecretKey object (bobAes on Bob, aliceAes on Alice).
                        // In a real protocol you'll typically export the key material (e.g., key.getEncoded())
                        // and use a KDF to derive multiple keys (encryption, MAC, etc.). Here we use AES directly.

                        // -----------------------------------------------------------------
                        // STEP 6: Use the derived AES key with AES/GCM for authenticated encryption
                        // -----------------------------------------------------------------
                        // AES-GCM details and best practices:
                        //  - Use a fresh, unique 96-bit IV (nonce) per encryption under the same key.
                        //  - Use at least a 96-bit IV and a 128-bit authentication tag (GCMParameterSpec(128, iv)).
                        //  - Never reuse IV+key pair; doing so catastrophically breaks confidentiality.
                        //  - Include application-specific AAD (additional authenticated data) if needed for context binding.
                        try {
                            byte[] iv = new byte[12]; // 96-bit IV recommended for GCM
                            secureRandom.nextBytes(iv); // Fresh nonce
                            GCMParameterSpec gcm = new GCMParameterSpec(128, iv);

                            String plaintext = "post-quantum secure channel";
                            byte[] pt = plaintext.getBytes(StandardCharsets.UTF_8);

                            // Create and initialize the AES/GCM cipher for encryption.
                            Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding");
                            encCipher.init(Cipher.ENCRYPT_MODE, bobAes, gcm, secureRandom);

                            // Perform encryption (this produces ciphertext || tag).
                            byte[] ct = encCipher.doFinal(pt);

                            // In a real system you'd transmit (iv || ct) to Alice. Here we keep them in memory.
                            logger.info("AES/GCM ciphertext length: " + ct.length);

                            // -----------------------------------------------------------------
                            // STEP 7: Alice decrypts with AES/GCM using the shared key and same IV
                            // -----------------------------------------------------------------
                            try {
                                Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding");
                                // IMPORTANT: The same IV and tag length must be used for decryption.
                                decCipher.init(Cipher.DECRYPT_MODE, aliceAes, gcm);
                                byte[] recovered = decCipher.doFinal(ct);

                                // -----------------------------------------------------------------
                                // STEP 8: Final verification and cleanup notes
                                // -----------------------------------------------------------------
                                logger.info("\n=== Demo Results ===");
                                logger.info("ML-KEM encapsulation size:  " + kemMessage.length + " bytes");
                                logger.info("AES-GCM ciphertext (hex):   " + HexFormat.of().formatHex(ct));
                                logger.info("Recovered plaintext:        " + new String(recovered, StandardCharsets.UTF_8));

                                // Use constant-time comparison in production to avoid timing attacks.
                                if (Arrays.equals(pt, recovered)) {
                                    logger.info("Verification successful (decrypted text matches original)");
                                } else {
                                    logger.warning("Verification failed (mismatch detected)");
                                }

                                // Production cleanup suggestions (not implemented here):
                                //  - Overwrite sensitive byte arrays with zero (Arrays.fill) after use.
                                //  - If SecretKey implements Destroyable, call destroy().
                                //  - Use secure key storage (keystore/HSM), avoid keeping raw keys in heap.
                            } catch (GeneralSecurityException e) {
                                // Decryption can fail for multiple reasons:
                                //  - Authentication tag mismatch (tampered ciphertext or wrong key/IV)
                                //  - Algorithm not available or invalid parameters
                                logger.log(Level.SEVERE, "AES decryption failed", e);
                            }

                        } catch (GeneralSecurityException e) {
                            // Encryption errors: invalid key, wrong algorithm or provider issue.
                            logger.log(Level.SEVERE, "AES encryption failed", e);
                        }

                    } catch (GeneralSecurityException e) {
                        // Decapsulation problems:
                        //  - Wrong private key, malformed capsule, or provider internal error.
                        logger.log(Level.SEVERE, "KEM decapsulation failed", e);
                    }

                } catch (GeneralSecurityException e) {
                    // Encapsulation problems:
                    //  - Provider doesn't support requested KEM, invalid public key, or internal error.
                    logger.log(Level.SEVERE, "KEM encapsulation failed", e);
                }

            } catch (GeneralSecurityException e) {
                // Key export/import problems:
                //  - KeyFactory not available for KEM family, encoding corrupted, or provider mismatch.
                logger.log(Level.SEVERE, "Key export/import failed", e);
            }

        } catch (GeneralSecurityException e) {
            // High-level failure in randomness or key generation:
            //  - No suitable SecureRandom algorithm, provider missing, or entropy source error.
            logger.log(Level.SEVERE, "Key generation or randomness failed", e);
        } catch (Exception e) {
            // Catch-all for any unexpected runtime exceptions that are not GeneralSecurityException.
            logger.log(Level.SEVERE, "Unexpected error", e);
        }
    }
}
*/
