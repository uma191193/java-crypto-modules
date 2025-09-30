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

*/
/**
 * ML_KEM_Mechanism_V2
 * -------------------
 * This version demonstrates three things:
 * 1) Using *parameter-set specific* algorithm names for ML-KEM:
 * "ML-KEM-512", "ML-KEM-768", or "ML-KEM-1024".
 * These names select the exact FIPS 203 parameter set without needing NamedParameterSpec.
 * 2) Using KeyFactory with ML-KEM to:
 * - Export keys to their standard encodings (X.509 for public, PKCS#8 for private),
 * - Reconstruct fresh key objects from those encodings,
 * - And then use the reconstructed keys for KEM encapsulation/decapsulation.
 * 3) Running the same AES/GCM encryption demo, proving that both parties derived the same key.
 * Why KeyFactory matters:
 * In real systems you rarely pass Key objects directly across processes/machines. Instead, you store
 * or transmit *encoded bytes* (e.g., put them in a file, a DB, a certificate, or send over the wire).
 * KeyFactory is the JCA/JCE bridge that turns between:
 * - Encoded forms <-> Java Key objects
 * This is essential for interoperability and persistence.
 *//*

public class ML_KEM_Mechanism_V2 {


    public static void main(String[] args) throws Exception {

        // ---------------------------------------------------------------------
        // Choose the exact ML-KEM parameter set by name.
        // Valid choices (in order of increasing security & size): "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024".
        // Tip: "ML-KEM" (family name) also works, but then you’d configure the parameter set separately.
        // Here we pick the strongest set explicitly:
        // ---------------------------------------------------------------------
        final String KEM_ALGORITHM = "ML-KEM";

        // ---------------------------------------------------------------------
        // A strong cryptographic RNG. getInstanceStrong() will choose a system-strong PRNG
        // (e.g., on Linux: NativePRNGNonBlocking / DRBG backed by /dev/urandom).
        // This RNG is used for keygen AND for KEM encapsulation randomness.
        // ---------------------------------------------------------------------
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();

        // ---------------------------------------------------------------------
        // STEP 1: Receiver (Alice) generates an ML-KEM keypair
        // Using the *parameter-set specific* algorithm name for KeyPairGenerator.
        // No NamedParameterSpec is needed because the name already “locks in” the set (FIPS 203).
        // ---------------------------------------------------------------------
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEM_ALGORITHM);
        System.out.println("KeyPairGenerator algorithm is : " + keyPairGenerator.getAlgorithm());
        KeyPair aliceKeyPair = keyPairGenerator.generateKeyPair();

        // A few quick facts about the keys we just generated:
        // - key.getAlgorithm() is the *family* name ("ML-KEM"), even if we requested "ML-KEM-1024".
        // - key.getParams() (via AsymmetricKey default method) should return a NamedParameterSpec
        //   whose name matches the parameter set ("ML-KEM-1024" here).
        System.out.println("Public key algorithm (family): " + aliceKeyPair.getPublic().getAlgorithm());
        AlgorithmParameterSpec params = ((AsymmetricKey) aliceKeyPair.getPublic()).getParams();
        if (params instanceof NamedParameterSpec named) {
            System.out.println("Public key parameter set:    " + named.getName());
        }
        //System.out.println("KeyPairGenerator provider:    " + keyPairGenerator.getProvider().getName());

        // ---------------------------------------------------------------------
        // STEP 2: Use KeyFactory to serialize and reconstruct keys
        // ---------------------------------------------------------------------
        // Why do this? In real life, Alice would STORE/SEND the encoded public key; Bob would
        // RECONSTRUCT it on his side. Likewise for Alice’s private key when loading from storage.
        // Encodings (these are standardized wire/storage formats):
        //   - Public key  -> X.509 SubjectPublicKeyInfo (SPKI)
        //   - Private key -> PKCS#8 PrivateKeyInfo
        //
        // We instantiate KeyFactory with the *same parameter-set name*. A KeyFactory created
        // with "ML-KEM-1024" will only accept ML-KEM-1024 keys; passing a key of another set
        // would cause InvalidKeySpecException/InvalidKeyException.
        // (If you used the family name "ML-KEM", the factory could handle any ML-KEM set.)
        // ---------------------------------------------------------------------
        KeyFactory keyFactory = KeyFactory.getInstance(KEM_ALGORITHM);

        System.out.println("KeyFactory algorithm is : " + PQCParameterInspector_V2.detectDefaultParam(KEM_ALGORITHM));

        // --- Encode (export) to standard formats
        byte[] x509Pub = aliceKeyPair.getPublic().getEncoded();   // X.509/SPKI
        byte[] pkcs8Pri = aliceKeyPair.getPrivate().getEncoded();  // PKCS#8

        // --- Rebuild (import) from encodings
        PublicKey alicePublicFromBytes = keyFactory.generatePublic(new X509EncodedKeySpec(x509Pub));
        PrivateKey alicePrivateFromBytes = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Pri));

        // Sanity check: parameter set survives round trip
        AlgorithmParameterSpec rebuiltParams = ((AsymmetricKey) alicePublicFromBytes).getParams();
        if (rebuiltParams instanceof NamedParameterSpec named2) {
            System.out.println("Rebuilt public param set : " + named2.getName());
        }

        // ---------------------------------------------------------------------
        // STEP 3: Sender (Bob) encapsulates *to Alice’s public key* to derive a symmetric key
        // ---------------------------------------------------------------------
        // We obtain a KEM instance bound to the same parameter set name.
        // Encapsulation creates:
        //   - a random "encapsulation message" (aka KEM ciphertext) to ship to Alice, and
        //   - a shared secret (here we request 32 bytes and ask the provider to wrap it as an "AES" SecretKey).
        // That 32-byte key will be used as AES-256 for GCM.
        KEM kem = KEM.getInstance(KEM_ALGORITHM);
        KEM.Encapsulator encapsulator = kem.newEncapsulator(alicePublicFromBytes, secureRandom);

        // encapsulate(offset, length, keyAlg)
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");
        SecretKey bobAes = encapsulated.key();            // Bob’s shared AES-256 key
        byte[] kemMessage = encapsulated.encapsulation(); // Bob sends this byte[] to Alice

        // FYI: The size of kemMessage depends on the ML-KEM set:
        //   ~768 bytes for ML-KEM-512, ~1088 for ML-KEM-768, ~1568 for ML-KEM-1024 (per FIPS 203).

        // ---------------------------------------------------------------------
        // STEP 4: Receiver (Alice) decapsulates using her private key to get the *same* AES key
        // ---------------------------------------------------------------------
        KEM.Decapsulator decapsulator = kem.newDecapsulator(alicePrivateFromBytes);
        SecretKey aliceAes = decapsulator.decapsulate(kemMessage, 0, 32, "AES");

        // ---------------------------------------------------------------------
        // STEP 5: Use the shared AES-256 key with AES/GCM for authenticated encryption
        // ---------------------------------------------------------------------
        byte[] iv = new byte[12];                 // 96-bit IV is the GCM standard recommendation
        secureRandom.nextBytes(iv);               // Always use a fresh, unique IV per message
        GCMParameterSpec gcm = new GCMParameterSpec(128, iv); // 128-bit auth tag

        String plaintext = "post-quantum secure channel";
        byte[] pt = plaintext.getBytes(StandardCharsets.UTF_8);

        Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encCipher.init(Cipher.ENCRYPT_MODE, bobAes, gcm, secureRandom);
        byte[] ct = encCipher.doFinal(pt);

        // ---------------------------------------------------------------------
        // STEP 6: Decrypt on Alice’s side with her derived AES key
        // ---------------------------------------------------------------------
        Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding");
        decCipher.init(Cipher.DECRYPT_MODE, aliceAes, gcm);
        byte[] recovered = decCipher.doFinal(ct);

        // ---------------------------------------------------------------------
        // STEP 7: Print results & verify
        // ---------------------------------------------------------------------
        //System.out.println("KEM provider:                  " + kem.getAlgorithm());
        System.out.println("ML-KEM encapsulation size:     " + kemMessage.length + " bytes");
        System.out.println("AES-GCM ciphertext (hex):      " + HexFormat.of().formatHex(ct));
        System.out.println("Recovered:                     " + new String(recovered, StandardCharsets.UTF_8));

        // Only for testing: alter one byte of recovered text
        //recovered[0] ^= 0x01;  // flip a bit → ensures mismatch
        if (Arrays.equals(pt, recovered)) {
            System.out.println("Verification successful: Decrypted text matches original!");
        } else {
            System.out.println("Verification failed: Mismatch detected!");
        }
    }
}*/
