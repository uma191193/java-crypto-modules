/*
package jjwt_13;

// Import required JJWT and Java security classes

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class AsymmetricJweExample_13 {
    public static void main(String[] args) {

        // ============================================================
        // Step 1: Generate RSA Key Pair (Asymmetric Key Generation)
        // ============================================================

        */
/*
         * JJWT provides helper methods to easily generate secure key pairs.
         * Here, we generate a 2048-bit RSA key pair suitable for signing/encryption.
         *
         * RS512 refers to RSA with SHA-512 (used for signing if needed).
         * In this example, we're only using the key pair for encryption (JWE).
         *//*

        KeyPair rsaPair = Jwts.SIG.RS512.keyPair().build();

        // Extracting public and private keys (optional, for clarity)
        PublicKey publicKey = rsaPair.getPublic();   // Used to encrypt
        PrivateKey privateKey = rsaPair.getPrivate(); // Used to decrypt

        // ============================================================
        // Step 2: Define Algorithms for Encryption
        // ============================================================

        */
/*
         * Key Algorithm: RSA-OAEP-256
         * ----------------------------
         * - This is an RSA-based key encryption algorithm (RSA with OAEP padding and SHA-256).
         * - Used to wrap the symmetric AES key used for encrypting the payload.
         *
         * Content Encryption Algorithm: AES-256-GCM (A256GCM)
         * ---------------------------------------------------
         * - This is the algorithm used to encrypt the actual content (JWT claims).
         * - AES-GCM provides both confidentiality and integrity.
         *//*

        KeyAlgorithm<PublicKey, PrivateKey> keyAlg = Jwts.KEY.RSA_OAEP_256;
        AeadAlgorithm encAlg = Jwts.ENC.A256GCM;

        // ============================================================
        // Step 3: Encrypt JWT Claims Using Asymmetric JWE
        // ============================================================

        */
/*
         * In this example, we are building an encrypted JWT (JWE) using the public key.
         * By default, JJWT includes standard claims like `iat` (issued at).
         *
         * Note: If you want to include custom claims, you can add `.claim(...)` before `.encryptWith(...)`.
         *//*

        String jwe = Jwts.builder()
                .encryptWith(publicKey, keyAlg, encAlg) // Encrypt with public key using RSA-OAEP-256 and AES-GCM
                .compact();                             // Serialize the JWE to a compact string

        // Output the encrypted token
        System.out.println("Encrypted JWE: " + jwe);

        // ============================================================
        // Step 4: Decrypt the JWE Token Using Private Key
        // ============================================================

        */
/*
         * To decrypt the token, we must use the **private key** that corresponds to the public key used in encryption.
         * This ensures that only the holder of the private key can read the content.
         *//*

        Claims claims = Jwts.parser()
                .decryptWith(privateKey)              // Decrypt using the private key
                .build()                              // Build the parser
                .parseEncryptedClaims(jwe)            // Parse and decrypt the encrypted JWT string
                .getPayload();                        // Get the decrypted JWT claims (body)

        // ============================================================
        // Step 5: Display Decrypted Claims
        // ============================================================

        // Print the decrypted claims. If no custom claims were set, output will include default fields like `iat`.
        System.out.println("Decrypted claims: " + claims);
    }
}*/
