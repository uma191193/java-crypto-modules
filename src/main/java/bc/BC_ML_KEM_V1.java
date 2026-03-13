package bc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.*;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;

public class BC_ML_KEM_V1 {
    public static void main(String[] args) {

        System.out.println("=== ML-KEM (Kyber) Lightweight API Demo ===");
        SecureRandom random = new SecureRandom();

        // 1. Key Generation (Lightweight Style)
        // No JCA "BCPQC" provider needed here
        MLKEMKeyPairGenerator kpg = new MLKEMKeyPairGenerator();
        kpg.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        // These are the raw parameter objects
        MLKEMPublicKeyParameters pubParams = (MLKEMPublicKeyParameters) kp.getPublic();
        MLKEMPrivateKeyParameters privParams = (MLKEMPrivateKeyParameters) kp.getPrivate();

        // 2. Encapsulation (Alice)
        // Directly pass the pubParams object
        MLKEMGenerator kemGen = new MLKEMGenerator(random);
        SecretWithEncapsulation kemSecret = kemGen.generateEncapsulated(pubParams);

        byte[] aliceSharedSecret = kemSecret.getSecret();
        byte[] encapsulationCiphertext = kemSecret.getEncapsulation();

        System.out.println("Encapsulation length: " + encapsulationCiphertext.length + " bytes");
        System.out.println("Alice's Shared Secret: " + Hex.toHexString(aliceSharedSecret));

        // 3. Decapsulation (Bob)
        // Directly pass the privParams object
        MLKEMExtractor kemExt = new MLKEMExtractor(privParams);
        byte[] bobSharedSecret = kemExt.extractSecret(encapsulationCiphertext);

        System.out.println("Bob's Shared Secret  : " + Hex.toHexString(bobSharedSecret));

        // 4. Verify
        boolean match = Arrays.constantTimeAreEqual(aliceSharedSecret, bobSharedSecret);
        System.out.println("Shared secrets match: " + match);
    }
}