package cb.lab.digitalSignature;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

@Service
public class DigitalSignatureService {
    byte[] getMD5Hash(MultipartFile file) throws NoSuchAlgorithmException, IOException {
            return new BigInteger(
                    1, MessageDigest
                    .getInstance("MD5")
                    .digest(file.getBytes())
            )
            .toString(16)
            .getBytes(StandardCharsets.UTF_8);
    }

    byte[] getUltraWeakHash(MultipartFile file) throws IOException {
        int hash = 0;

        for (byte b : file.getBytes()) {
            hash += b;
        }

        return new byte[] {(byte)(hash)};
    }

    byte[] getDocumentHash(MultipartFile file, boolean weakHash) throws NoSuchAlgorithmException, IOException {
        return !weakHash ? getMD5Hash(file) : getUltraWeakHash(file);
    }

    PrivateKey parsePrivateKey(MultipartFile privateKeyFile) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        String privateKeyContent = new String(privateKeyFile.getBytes(), StandardCharsets.UTF_8);
        String privateKeyPem = privateKeyContent
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decodedPrivateKey = Base64.getDecoder().decode(privateKeyPem);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decodedPrivateKey));
    }

    PublicKey parsePublicKey(MultipartFile publicKeyFile) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        String publicKeyContent = new String(publicKeyFile.getBytes(), StandardCharsets.UTF_8);
        String publicPem = publicKeyContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decodedPublicKey = Base64.getDecoder().decode(publicPem);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedPublicKey));
    }

    String makeCertificate(byte[] hashBytes, PrivateKey privateKey, String name, boolean weakHash) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        String signature = Base64.getEncoder().encodeToString(encryptCipher.doFinal(hashBytes));

        return String.format(
                "-----BEGIN DIGITAL SIGNATURE-----\n" +
                        "Algorithm: %s + user RSA key\n" +
                        "Signature: %s\n" +
                        "Signed: %s by Team15\n" +
                        "Created by %s\n" +
                        "-----END DIGITAL SIGNATURE-----",
                weakHash ? "weak hash(sum)" : "MD5",
                signature,
                Instant.now().toString(),
                name
        );
    }

    boolean checkFingerprint(byte[] hashBytes, String base64signature, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, publicKey);
        return Arrays.equals(decryptCipher.doFinal(Base64.getDecoder().decode(base64signature)), hashBytes);
    }
}
