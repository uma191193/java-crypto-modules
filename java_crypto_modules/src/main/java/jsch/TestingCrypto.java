/*
package jsch;

// Import necessary classes from the JSch library

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.KeyPair;
import com.jcraft.jsch.KeyPairRSA;

import java.util.Arrays;

public class TestingCrypto {

    public static void main(String[] args) {

        // Step 1: Create a new instance of the JSch class
        // JSch acts as the controller to manage key pairs, sessions, and identities
        JSch jsch = new JSch();

        // Step 2: Define the path to the existing private key file (RSA or DSA format)
        String privateKeyPath = "C:\\Users\\UmaMaheswar\\Testing\\my_private_key"; // Update this path accordingly

        // Step 3: Provide the passphrase used to encrypt the private key (if any)
        String passphrase = "mykey123"; // Replace with actual passphrase if your key is encrypted

        try {
            // Step 4: Load the existing key pair from the given file path
            // This reads both public and private key information from the file
            KeyPair kpair = KeyPair.load(jsch, privateKeyPath);

            */
/*
            // [Optional]: You can uncomment the following lines to generate and save new key pairs

            // Example: Generate an RSA key (2 = KeyPair.RSA)
            KeyPair kpair = KeyPair.genKeyPair(jsch, 2);
            kpair.writePrivateKey("...path...");
            kpair.writePublicKey("...path...", "comment");

            // Example: Generate a DSA key (1 = KeyPair.DSA)
            KeyPair kpair = KeyPair.genKeyPair(jsch, 1);

            // Example: Generate ECDSA key with curve size 256
            KeyPair kpair = KeyPair.genKeyPair(jsch, KeyPair.ECDSA, 256);
            *//*


            // Step 5: Create a new KeyPairRSA manually (used here only for demo, not linked to `kpair`)
            // This constructor alone does not load key data — you must manually set modulus, exponents etc. (not shown here)
            KeyPairRSA keyPairRSA = new KeyPairRSA(jsch);

            // Step 6: Attempt to generate a signature from raw data using the above keyPairRSA (note: this RSA object is empty!)
            // So this line will NOT work correctly unless the internal key material is set manually
            // This call is for demo only — without a key, it returns null or throws exception
            System.out.println(Arrays.toString(keyPairRSA.getSignature("mytestpass".getBytes())));

            // Step 7: Check if the loaded private key from file is encrypted
            if (kpair.isEncrypted()) {
                System.out.println("Private key is encrypted. Attempting to decrypt...");

                // Step 8: Decrypt the private key using the passphrase
                if (kpair.decrypt(passphrase)) {
                    // Successful decryption
                    System.out.println("Private key decrypted successfully.");

                    // Optional: Print the key type (RSA = 2, DSA = 1, ECDSA = 3, etc.)
                    System.out.println("Key Type is " + kpair.getKeyType());

                    // After decryption, you can use this key for authentication, digital signature, etc.
                    // e.g., jsch.addIdentity(kpair); ← if you were setting up an SSH session

                } else {
                    // Decryption failed (wrong passphrase)
                    System.err.println("Failed to decrypt private key. Incorrect passphrase.");
                }

            } else {
                // The private key is not encrypted, so it's ready to use
                System.out.println("Private key is not encrypted.");
            }

            // Step 9: Clean up sensitive information in memory
            // Always dispose of cryptographic objects after use to reduce memory exposure
            kpair.dispose();

        } catch (JSchException e) {
            // Handles JSch-specific errors such as file I/O, decryption failure, or internal exceptions
            System.err.println("JSchException: " + e.getMessage());
        }
    }
}
*/
