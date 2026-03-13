/*
package jdk_24;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.util.HexFormat;

*/
/**
 * Demonstration of Post-Quantum Digital Signatures in Java 24 using ML-DSA.
 * ML-DSA (Module-Lattice Digital Signature Algorithm) is the standardized version of
 * CRYSTALS-Dilithium, chosen by NIST as the post-quantum replacement for RSA/ECDSA.
 * In Java 24, it is exposed through the standard JCA (Java Cryptography Architecture)
 * APIs, so you use it just like "RSA" or "EC".
 *//*

public class ML_DSA_Signature_V1 {
    public static void main(String[] args) throws Exception {

        */
/*
         * STEP 1: Generate a keypair
         * --------------------------
         * - "ML-DSA" is the algorithm name recognized by Java 24's JCA providers.
         * - We pick a parameter set using NamedParameterSpec:
         *      - ML_DSA_44 → security level 1 (128-bit classical security)
         *      - ML_DSA_65 → security level 3 (192-bit classical security) [DEFAULT]
         *      - ML_DSA_87 → security level 5 (256-bit classical security)
         * - Higher levels mean bigger keys/signatures but stronger security.
         *//*

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA");

        //If we comment all the initialization by default it will be ML_DSA_65 and picks level 3.
        keyPairGenerator.initialize(NamedParameterSpec.ML_DSA_44); // here we pick level 1 security-2420 bytes signature proved
        //keyPairGenerator.initialize(NamedParameterSpec.ML_DSA_65); // here we pick level 3 security-3309 bytes signature proved
        //keyPairGenerator.initialize(NamedParameterSpec.ML_DSA_87); // here we pick level 5 security-4627 bytes signature proved

        //System.out.println("KeyPairGenerator algorithm is : " + keyPairGenerator.getAlgorithm());
        //System.out.println("KeyPairGenerator provider is : " + keyPairGenerator.getProvider());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        //System.out.println("Public key is : " + keyPair.getPublic());
        //System.out.println("Private key is : " + keyPair.getPrivate());
        //System.out.println("Public key algorithm is : " + keyPair.getPublic().getAlgorithm());
        //System.out.println("Private key algorithm is : " + keyPair.getPrivate().getAlgorithm());
        //System.out.println("Public key format is : " + keyPair.getPublic().getFormat());
        //System.out.println("Private key format is : " + keyPair.getPrivate().getFormat());

        */
/*
         * STEP 2: Prepare a inputMessage to signature
         * ---------------------------------
         * We're just signing a short string here, but in practice you signature hashes of
         * larger data (like in digital certificates or code signing).
         *//*

        byte[] inputMessage = "hello, post-quantum Java 24".getBytes(StandardCharsets.UTF_8);

        */
/*
         * STEP 3: Create and initialize a Signature object for signing
         * ------------------------------------------------------------
         * - Signature.getInstance("ML-DSA") tells Java we want to use the ML-DSA algorithm.
         * - initSign(privateKey) loads our private key, since only the private key
         *   holder can generate a valid finalSignature.
         *//*

        Signature signature = Signature.getInstance("ML-DSA-44");
        System.out.println("Signature algorithm : " + signature.getAlgorithm());
        signature.initSign(keyPair.getPrivate());
        signature.update(inputMessage);       // feed in the inputMessage
        byte[] finalSignature = signature.sign(); // produce the finalSignature bytes

        */
/*
         * STEP 4: Verify the finalSignature
         * -----------------------------
         * - Verification requires the *public key*, so anyone can check validity
         *   without knowing the private key.
         * - If the inputMessage was altered or signed with a different key, verification fails.
         *//*

        Signature verification = Signature.getInstance("ML-DSA-44");
        verification.initVerify(keyPair.getPublic());
        verification.update(inputMessage);
        boolean verified = verification.verify(finalSignature);

        */
/*
         * STEP 5: Print results
         * ----------------------
         * - Signatures in ML-DSA are larger than RSA/ECDSA (kilobytes instead of bytes),
         *   but they’re still efficient for many real-world applications.
         *//*

        System.out.println("ML-DSA finalSignature length: " + finalSignature.length + " bytes");
        System.out.println("Verify result: " + verified);
        System.out.println("Signature (hex): " + HexFormat.of().formatHex(finalSignature));
    }
}*/
