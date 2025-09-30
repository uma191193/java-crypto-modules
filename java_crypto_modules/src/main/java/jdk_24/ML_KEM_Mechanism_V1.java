/*
package jdk_24;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.HexFormat;

*/
/**
 * Demonstration of Post-Quantum Key Encapsulation in Java 24 using ML-KEM.
 * ML-KEM (Module-Lattice Key Encapsulation Mechanism) is the standardized
 * version of CRYSTALS-Kyber, chosen by NIST as the post-quantum replacement
 * for RSA/ECDH key exchange.
 * In this demo, we use ML-KEM to derive a shared AES-256 key between
 * two parties (Alice & Bob) and then use that key with AES/GCM to
 * encrypt and decrypt a message.
 *//*

public class ML_KEM_Mechanism_V1 {
    public static void main(String[] args) throws Exception {

        */
/*SecureRandom is a class in the java.security package.
         * It provides a cryptographically strong source of randomness,
         * unlike java.util.Random, which is not secure for cryptographic use.
         *//*

        SecureRandom secureRandom = SecureRandom.getInstanceStrong();

        */
/*
         * STEP 1: Receiver (Alice) generates her ML-KEM keypair
         * -----------------------------------------------------
         * - "ML-KEM" is the algorithm name in JDK 24.
         * - Just like ML-DSA, ML-KEM has three parameter sets:
         *      ML_KEM_512 → security level 1 (128-bit classical security)
         *      ML_KEM_768 → security level 3 (192-bit classical security) [DEFAULT]
         *      ML_KEM_1024 → security level 5 (256-bit classical security)
         * - Here we explicitly choose ML_KEM_1024 (the strongest set).
         *//*

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-KEM");

        //If we comment the initialization by default it will be ML_KEM_768 and picks level 3.
        keyPairGenerator.initialize(NamedParameterSpec.ML_KEM_512); //here we pick level 1 security-768 bytes proved
        //keyPairGenerator.initialize(NamedParameterSpec.ML_KEM_768); //here we pick level 3 security-1088 bytes proved
        //keyPairGenerator.initialize(NamedParameterSpec.ML_KEM_1024); //here we pick level 5 security-1568 bytes proved

        //System.out.println("KeyPairGenerator algorithm is : " + keyPairGenerator.getAlgorithm());
        //System.out.println("KeyPairGenerator provider is : " + keyPairGenerator.getProvider());

        KeyPair aliceKem = keyPairGenerator.generateKeyPair();

        //Prints the Algorithm information
        System.out.println("Algorithm: " + aliceKem.getPublic().getAlgorithm());
        if (aliceKem.getPublic().getParams() instanceof NamedParameterSpec spec) {
            System.out.println("Parameter Set: " + spec.getName());
        }

        //System.out.println("Public key is : " + aliceKem.getPublic());
        //System.out.println("Private key is : " + aliceKem.getPrivate());
        //System.out.println("Public key algorithm is : " + aliceKem.getPublic().getAlgorithm());
        //System.out.println("Private key algorithm is : " + aliceKem.getPrivate().getAlgorithm());
        //System.out.println("Public key format is : " + aliceKem.getPublic().getFormat());
        //System.out.println("Private key format is : " + aliceKem.getPrivate().getFormat());

        */
/*
         * STEP 2: Sender (Bob) encapsulates to Alice’s public key
         * -------------------------------------------------------
         * - Bob uses Alice’s *public key* to generate:
         *      (a) A random "encapsulation blob" (kemMessage)
         *      (b) A symmetric key derived from that encapsulation
         * - Bob asks ML-KEM to give him a 32-byte AES key (AES-256).
         * - The encapsulation blob must be sent to Alice.
         *//*

        KEM kem = KEM.getInstance("ML-KEM");
        KEM.Encapsulator encapsulator = kem.newEncapsulator(aliceKem.getPublic(), secureRandom);
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");

        SecretKey bobAes = encapsulated.key();              // Bob’s derived AES-256 key
        byte[] kemMessage = encapsulated.encapsulation();   // Must be sent to Alice

        */
/*
         * STEP 3: Receiver (Alice) decapsulates to recover the AES key
         * ------------------------------------------------------------
         * - Alice uses her private key + Bob’s encapsulation blob.
         * - This yields the *exact same AES-256 key* as Bob derived.
         * - Now both sides share the same secret without ever sending
         *   the key directly over the network.
         *//*

        KEM.Decapsulator decapsulator = kem.newDecapsulator(aliceKem.getPrivate());
        SecretKey aliceAes = decapsulator.decapsulate(kemMessage, 0, 32, "AES");

        */
/*
         * STEP 4: Encrypt a message using AES/GCM
         * ---------------------------------------
         * - Now that both sides have the same AES-256 key,
         *   they can use it as a secure channel.
         * - We encrypt plaintext with AES in GCM mode (provides
         *   both confidentiality + integrity).
         *//*

        byte[] iv = new byte[12];  // 96-bit IV for GCM
        secureRandom.nextBytes(iv);
        GCMParameterSpec gcm = new GCMParameterSpec(128, iv);

        String plaintext = "post-quantum secure channel";
        byte[] pt = plaintext.getBytes(StandardCharsets.UTF_8);

        Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encCipher.init(Cipher.ENCRYPT_MODE, bobAes, gcm, secureRandom);
        byte[] ct = encCipher.doFinal(pt);

        */
/*
         * STEP 5: Decrypt the ciphertext on Alice’s side
         * ----------------------------------------------
         * - Alice uses her AES key (derived via ML-KEM decapsulation).
         * - If the shared key matches, decryption works and recovers
         *   the exact plaintext.
         * - If an attacker modified the ciphertext, GCM would detect it
         *   and throw an exception.
         *//*

        Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding");
        decCipher.init(Cipher.DECRYPT_MODE, aliceAes, gcm);
        byte[] recovered = decCipher.doFinal(ct);

        */
/*
         * STEP 6: Print results
         * ----------------------
         * - Shows encapsulation blob size (in bytes).
         * - Displays AES-GCM ciphertext in hex.
         * - Confirms decrypted text matches original.
         *//*

        System.out.println("ML-KEM encapsulation size: " + kemMessage.length + " bytes");
        System.out.println("AES-GCM ciphertext (hex): " + HexFormat.of().formatHex(ct));
        System.out.println("Recovered: " + new String(recovered, StandardCharsets.UTF_8));

        */
/*
         * STEP 7: Verification
         * ----------------------
         * - Compare original plaintext(pt) nothing but our input with recovered(decrypted) plaintext.
         * - Verify whether decryption was successful.
         *//*


        // For testing: alter one byte of recovered text
        //recovered[0] ^= 0x01;  // flip a bit → ensures mismatch
        if (Arrays.equals(pt, recovered)) {
            System.out.println("Verification successful: Decrypted text matches original!");
        } else {
            System.out.println("Verification failed: Mismatch detected! " + new String(recovered, StandardCharsets.UTF_8));
        }
    }
}*/
