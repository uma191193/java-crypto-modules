/*
package jjwt_13;

// Import classes from the JJWT library and Java standard APIs

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.AeadAlgorithm;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

public class SymmetricJweExample_13 {
    public static void main(String[] args) {
        // ============================================================
        // Step 1: Select Encryption Algorithm and Generate Secret Key
        // ============================================================

        // JJWT provides built-in AEAD (Authenticated Encryption with Associated Data) algorithms.
        // Here, we select AES-GCM with a 256-bit key length (A256GCM), which is strong and efficient.
        AeadAlgorithm enc = Jwts.ENC.A256GCM;

        // This generates a secure 256-bit symmetric key suitable for A256GCM.
        // The same key will be used for both encryption and decryption (symmetric encryption).
        SecretKey key = enc.key().build();

        // ============================================================
        // Step 2: Prepare the Payload (Plaintext to be Encrypted)
        // ============================================================

        // Define the plaintext message that needs to be securely encrypted.
        String message = "Sensitive info";

        // Convert the message to a byte array using UTF-8 encoding.
        // JWE expects binary data, so the payload must be in byte form.
        byte[] payload = message.getBytes(StandardCharsets.UTF_8);

        // ============================================================
        // Step 3: Encrypt the Payload into a Compact JWE Token
        // ============================================================

        // Build and encrypt the JWT using the fluent JJWT builder API.
        String jwe = Jwts.builder()
                .content(payload, "text/plain")  // Set the content and media type (can be JSON, text, etc.)
                .encryptWith(key, enc)           // Encrypt using the symmetric key and selected algorithm
                .compact();                      // Serialize the result into a compact, URL-safe JWE string

        // Print the final JWE string (Base64URL-encoded format, contains 5 parts: header, encrypted key, IV, ciphertext, tag)
        System.out.println("Encrypted JWE: " + jwe);

        // ============================================================
        // Step 4: Decrypt the JWE Token to Get Original Content
        // ============================================================

        // Start building a parser to process the encrypted token.
        byte[] decrypted = Jwts.parser()
                .decryptWith(key)               // Provide the same symmetric key used for encryption
                .build()                        // Finalize the parser
                .parseEncryptedContent(jwe)     // Parse and decrypt the JWE string
                .getPayload();                  // Retrieve the decrypted payload (as byte[])

        // ============================================================
        // Step 5: Convert Decrypted Bytes Back to String and Print
        // ============================================================

        // Convert the decrypted bytes back to a string using UTF-8 (should match the original message)
        System.out.println("Decrypted payload: " + new String(decrypted, StandardCharsets.UTF_8));
    }
}*/
