package jsch;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.KeyPair;
import com.jcraft.jsch.KeyPairECDSA;
import com.jcraft.jsch.Signature;

public class TestingCryptoECDSA {

    public static void main(String[] args) throws Exception {

        // Step 1: Create an instance of JSch (core SSH and key utility manager)
        // This object is necessary for generating or loading key pairs using JSch
        JSch jsch = new JSch();

        // Step 2: Generate a (from 256 to 521) -bit ECDSA key pair
        // KeyPair.genKeyPair returns a KeyPair (abstract) which is cast here to KeyPairECDSA
        // KeyPairECDSA gives access to ECDSA-specific methods like getSignature
        KeyPairECDSA keyPairECDSA = (KeyPairECDSA) KeyPair.genKeyPair(jsch, KeyPair.ECDSA, 521);

        // Step 3: Prepare the data to be signed just consider this as sample data for testing
        // This simulates any important message or data whose integrity and authenticity you want to ensure
        // In real-world scenarios, this could be a file's contents, a hash, or a server-provided challenge
        byte[] data = "ImportantMessage".getBytes();

        // Step 4: Generate a digital signature using the ECDSA private key
        // The method signs the SHA-1 digest of the input data and returns the ECDSA signature
        // Internally, it does: signature = (SHA1(data))^d mod n, where d is the private exponent
        byte[] signature = keyPairECDSA.getSignature(data);

        // Step 5: Output the signature in a human-readable format (hex)
        // This is helpful for debugging, storing, or comparing signatures
        System.out.println("Signature (Hex): " + bytesToHex(signature));

        //Here comes the verification part
        // Step 6: Get a verifier initialized with the public key part of the ECDSA key pair
        Signature verifier = keyPairECDSA.getVerifier(); // Uses modulus and public exponent internally

        // Step 7: Feed the original data into the verifier
        verifier.update(data); // Internally hashes the data using SHA-1

        // Step 8: Verify the digital signature
        boolean isValid = verifier.verify(signature);

        // Step 9: Output the verification result
        System.out.println("Signature Valid ? " + isValid);

        // Step 10: Clear the private key material from memory
        // This is a crucial security step to reduce risk of memory-based key leaks
        keyPairECDSA.dispose();
    }

    /**
     * Utility method to convert a byte array into a hexadecimal string.
     * Useful for printing raw bytes like signatures or hashes in a readable form.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        // Each byte is converted to a 2-digit hex representation
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}