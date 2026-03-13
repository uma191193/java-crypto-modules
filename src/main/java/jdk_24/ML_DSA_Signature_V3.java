package jdk_24;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * ML_DSA_Signature_V3
 * -------------------
 * This program demonstrates the use of the ML-DSA algorithm family
 * (NIST FIPS 204 "Module-Lattice-based Digital Signature Algorithm")
 * available in Java SE 24 (JEP 496).
 * Goals of this demo:
 * 1) Use ONLY the *family name* "ML-DSA" when requesting algorithms.
 * - We never hardcode "ML-DSA-44", "ML-DSA-65", or "ML-DSA-87".
 * - This way, the JDK provider chooses its default parameter set.
 * - In JDK 24, the default is ML-DSA-65.
 * 2) Print/discover which parameter set was actually chosen by the provider:
 * - (a) Directly via NamedParameterSpec from the generated key.
 * - (b) Indirectly via OID parsing (using PQCParameterInspector_V2).
 * 3) Export keys (public in X.509/SPKI format, private in PKCS#8 format)
 * and re-import them with KeyFactory, verifying that the parameter set
 * survives a round-trip encoding/decoding process.
 * 4) Sign and verify a message using only the *family name* "ML-DSA".
 * - The parameter set embedded in the key determines the actual variant.
 * - For example, "ML-DSA" + default in JDK 24 → ML-DSA-65.
 * Notes:
 * - ML-DSA signatures are *much larger* than RSA/ECDSA, but are designed to
 * resist quantum computer attacks (post-quantum secure).
 * - This demo is educational: it shows parameter binding, round-trip safety,
 * and interoperability of the ML-DSA family in JDK 24.
 */
public class ML_DSA_Signature_V3 {

    private static final Logger logger = Logger.getLogger(ML_DSA_Signature_V3.class.getName());

    public static void main(String[] args) {

        // ---------------------------------------------------------------------
        // STEP 0: Define the algorithm family name
        // ---------------------------------------------------------------------
        // We deliberately request only the algorithm *family name* "ML-DSA".
        // By not specifying "-44", "-65", or "-87", we let the JDK provider
        // bind to its default parameter set (in JDK 24 this is ML-DSA-65).
        final String ML_DSA_FAMILY = "ML-DSA";

        try {
            // -----------------------------------------------------------------
            // STEP 1: Secure randomness
            // -----------------------------------------------------------------
            // SecureRandom provides the source of entropy (unpredictable bits).
            // - Used internally by the keypair generator.
            // - Also used by the Signature API during signing (for nonces).
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();

            // -----------------------------------------------------------------
            // STEP 2: Keypair generation (family name only)
            // -----------------------------------------------------------------
            // Ask the JDK for a KeyPairGenerator for "ML-DSA".
            // No parameters are supplied, so the default variant is chosen.
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ML_DSA_FAMILY);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Print basic algorithm information from the generator and keys.
            logger.info("=== Key Information ===");
            logger.info("KeyPairGenerator algorithm : " + keyPairGenerator.getAlgorithm());
            logger.info("KeyPairGenerator Public key family : " + keyPair.getPublic().getAlgorithm());

            // (A) Direct discovery of parameter set via NamedParameterSpec
            AlgorithmParameterSpec params = ((AsymmetricKey) keyPair.getPublic()).getParams();
            if (params instanceof NamedParameterSpec named) {
                logger.info("KeyPairGenerator Parameter set (NamedParameterSpec): " + named.getName());
            }

            // (B) Indirect discovery via OID lookup (if utility available).
            // PQCParameterInspector_V2 maps NIST OIDs to human-readable names:
            //   2.16.840.1.101.3.4.5.1 -> ML-DSA-44
            //   2.16.840.1.101.3.4.5.2 -> ML-DSA-65
            //   2.16.840.1.101.3.4.5.3 -> ML-DSA-87
            try {
                String detected = PQCParameterInspector_V2.detectDefaultParam(ML_DSA_FAMILY);
                logger.info("Parameter set (OID lookup) : " + detected);
            } catch (Exception e) {
                logger.log(Level.WARNING, "OID parameter detection failed: " + e.getMessage(), e);
            }

            // -----------------------------------------------------------------
            // STEP 3: Export and re-import the keys (round-trip check)
            // -----------------------------------------------------------------
            try {
                // KeyFactory converts between encoded key formats and live key objects.
                KeyFactory keyFactory = KeyFactory.getInstance(ML_DSA_FAMILY);

                // Export:
                // - Public key → X.509 SubjectPublicKeyInfo (SPKI)
                // - Private key → PKCS#8 PrivateKeyInfo
                byte[] x509Pub = keyPair.getPublic().getEncoded();
                byte[] pkcs8Pri = keyPair.getPrivate().getEncoded();

                // Rebuild the keys from encoded form.
                PublicKey rebuiltPub =
                        keyFactory.generatePublic(new X509EncodedKeySpec(x509Pub));
                PrivateKey rebuiltPri =
                        keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Pri));

                // Verify the parameter set is preserved after export/import.
                AlgorithmParameterSpec rebuiltParams = ((AsymmetricKey) rebuiltPub).getParams();
                String paramSetName = "unknown";
                if (rebuiltParams instanceof NamedParameterSpec named2) {
                    paramSetName = named2.getName();
                    logger.info("KeyFactory rebuilt public param set (NamedParameterSpec) : " + paramSetName);
                }

                // -----------------------------------------------------------------
                // STEP 4: Sign a message
                // -----------------------------------------------------------------
                // Prepare a test message for signing.
                byte[] message = "Hello, post-quantum Java 24 demo".getBytes(StandardCharsets.UTF_8);

                // Create a Signature instance for "ML-DSA" family.
                // Even though we pass only "ML-DSA", the key's parameters ensure
                // it binds to the correct variant (e.g., ML-DSA-65).
                Signature signer = Signature.getInstance(ML_DSA_FAMILY);

                // Initialize signer with private key + secure randomness.
                signer.initSign(rebuiltPri, secureRandom);

                // Feed the message into the signature engine.
                signer.update(message);

                // Compute the actual signature bytes.
                byte[] sig = signer.sign();
                logger.info("Signature signer algorithm : " + signer.getAlgorithm()
                        + " (bound to key param set: " + paramSetName + ")");
                // -----------------------------------------------------------------
                // STEP 5: Verify the signature
                // -----------------------------------------------------------------
                // Create a new Signature instance for verification (family name only).
                Signature verifier = Signature.getInstance(ML_DSA_FAMILY);

                // Initialize verifier with the corresponding public key.
                verifier.initVerify(rebuiltPub);

                // Provide the same message that was signed.
                verifier.update(message);

                // Check that the signature is valid.
                boolean verified = verifier.verify(sig);
                logger.info("Signature verifier algorithm: " + verifier.getAlgorithm()
                        + " (bound to key param set: " + paramSetName + ")");

                // -----------------------------------------------------------------
                // STEP 6: Print demo results
                // -----------------------------------------------------------------
                logger.info("\n=== Demo Results ===");
                logger.info("Signature length (bytes):  " + sig.length);
                logger.info("Verify result            :  " + verified);
                logger.info("Signature (hex, first 64): "
                        + HexFormat.of().formatHex(sig, 0, Math.min(sig.length, 32)) + "...");

            } catch (GeneralSecurityException e) {
                // Handle problems in key export/import or signing/verification process.
                logger.log(Level.SEVERE, "Key export/import or signature operation failed: " + e.getMessage(), e);
            }

        } catch (GeneralSecurityException e) {
            // Handle failures in randomness creation, key generation, or algorithm lookup.
            logger.log(Level.SEVERE, "Key generation or randomness failed: " + e.getMessage(), e);
        } catch (Exception e) {
            // Generic fallback for any unexpected error at runtime.
            logger.log(Level.SEVERE, "Unexpected error: " + e.getMessage(), e);
        }
    }
}