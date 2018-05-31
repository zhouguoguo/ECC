package sm2;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SignWithSM2 {

    public static String pubkeyBase64Str = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEBj2PmKye6dk+9CSDvkVV0vPdZGDf3xDOIAR7b6D2SNBkPd/YSKWuqyrlUIS4KFO/S9cTZoNFuq02UE5CCletlA==";
    public static String prikeyBase64Str = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgi19LGVs32+pFlcEn" +
            "Rcu7T4UWeBwbl6gagiF+sNfjNhWhRANCAAQGPY+YrJ7p2T70JIO+RVXS891kYN/f" +
            "EM4gBHtvoPZI0GQ939hIpa6rKuVQhLgoU79L1xNmg0W6rTZQTkIKV62U";

    public static String certBase64Str = "MIIB1DCCAXoCCQC5q2njdtURBDAKBggqgRzPVQGDdTByMQswCQYDVQQGEwJDTjEL" +
            "MAkGA1UECAwCU0gxCzAJBgNVBAcMAnNoMQowCAYDVQQKDAFhMQowCAYDVQQLDAFi" +
            "MQwwCgYDVQQDDANMYW4xIzAhBgkqhkiG9w0BCQEWFGxpYW5nLnpob3VAZmExMjMu" +
            "Y29tMB4XDTE4MDUyMzAxMzY1MFoXDTI4MDUyMDAxMzY1MFowcjELMAkGA1UEBhMC" +
            "Q04xCzAJBgNVBAgMAlNIMQswCQYDVQQHDAJzaDEKMAgGA1UECgwBYTEKMAgGA1UE" +
            "CwwBYjEMMAoGA1UEAwwDTGFuMSMwIQYJKoZIhvcNAQkBFhRsaWFuZy56aG91QGZh" +
            "MTIzLmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAY9j5isnunZPvQkg75F" +
            "VdLz3WRg398QziAEe2+g9kjQZD3f2Eilrqsq5VCEuChTv0vXE2aDRbqtNlBOQgpX" +
            "rZQwCgYIKoEcz1UBg3UDSAAwRQIhAIT9oM42wWe+xieO9DSJBhBstIAsWV3G9Uih" +
            "caP6+pADAiA2uQx0zQ5pZ2fwYmuDMJVL2WhckJS3mJZMzszE6gN/4Q==";

    public static String signKey = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKO4yScs85PCvnGen" +
            "WnQbz3aDbSIXKH7qQz/fK0a8hiWhRANCAATaYonPDi9M8PJyMsMgCFfzIUmqB6mO" +
            "1ftEA1aaYnZ32P0jBDpof34loW96ZbLc8XWJz1nj7mPzw2gxKIjUVKcZ";
    public static String vrfykey = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE2mKJzw4vTPDycjLDIAhX8yFJqgep" +
            "jtX7RANWmmJ2d9j9IwQ6aH9+JaFvemWy3PF1ic9Z4+5j88NoMSiI1FSnGQ==";

    public static PrivateKey buildPrivateKey(byte[] keyArray)
            throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyArray);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        return privateKey;
    }

    public static PublicKey buildPublicKey(byte[] keyArray)
            throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyArray);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        return publicKey;
    }

    public static byte[] Sign(byte[] prikey, byte[] data) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Signature ecdsaSign = Signature.getInstance("SM3WITHSM2");
        ecdsaSign.initSign(buildPrivateKey(prikey));
        ecdsaSign.update(data);
        byte[] signature = ecdsaSign.sign();

        return signature;
    }

    public static boolean verifyWithCert(byte[] cert, byte[] signed)
    {
        return true;
    }

    // Decode base64 encoded certificate
    public static Certificate buildCert(String base64) throws NoSuchProviderException {
        // Remove the first and last lines if exists
        String CertPEM = base64.replace("-----BEGIN CERTIFICATE-----", "");
        CertPEM = CertPEM.replace("-----END CERTIFICATE-----", "");
        System.out.println(CertPEM);

        // decode base64 string
        byte [] encoded = Base64.decode(CertPEM);

        // build Certificate
        CertificateFactory certFactory = null;
        try {
            certFactory = CertificateFactory.getInstance("X.509", "BC");
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        InputStream in = new ByteArrayInputStream(encoded);
        X509Certificate cert = null;
        try {
            cert = (X509Certificate)certFactory.generateCertificate(in);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return cert;
    }

    public static boolean verifyWithPubkey(byte[] pubkey, byte[] signed, byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Signature ecdsaVerify = Signature.getInstance("SM3WITHSM2");
        ecdsaVerify.initVerify(buildPublicKey(pubkey));
        ecdsaVerify.update(data);
        boolean result = ecdsaVerify.verify(signed);
        return result;
    }

    public static byte[] sm2Digest(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SM3");
        messageDigest.update(data);
        byte[] messageDigestMD5 = messageDigest.digest();
        return messageDigestMD5;
    }

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        String data = "123";
        byte[] dataBytes = data.getBytes("UTF-8");
        //byte[] signed = Sign(Base64.decode(prikeyBase64Str), dataBytes);

        //System.out.println(new String(Hex.encode(signed), "UTF-8"));
        //System.out.println(verifyWithPubkey(Base64.decode(pubkeyBase64Str), signed, dataBytes));

        Certificate cert = buildCert(certBase64Str);

        System.out.println(new String(Hex.encode(sm2Digest(dataBytes))));

    }
}
