package sm2;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class CertUtil {
    // Decode base64 encoded certificate
    public static X509Certificate buildCert(String base64)
    {
        // Remove the first and last lines if exists
        String CertPEM = base64.replace("-----BEGIN CERTIFICATE-----", "");
        CertPEM = CertPEM.replace("-----END CERTIFICATE-----", "");
        System.out.println(CertPEM);

        // decode base64 string
        byte [] encoded = Base64.decode(CertPEM);

        // build Certificate
        CertificateFactory certFactory = null;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
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

    // Build certificate chain
    public static X509Certificate[] buildChain(String[] certs)
    {
        System.out.println("certs.length = " + certs.length);
        X509Certificate[] chain = new X509Certificate[certs.length];
        for (int i=0; i<certs.length; ++i)
        {
            chain[i] = buildCert(certs[i]);
        }
        return chain;
    }

    public static String getEncodedFromIS(InputStream input) throws IOException {
        String encoded = "";
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));
        while (true) {
            String line = reader.readLine();
            if (line == null) break;
            encoded += line;
        }
        reader.close();
        System.out.println(encoded);
        return encoded;
    }

    // Decode base64 encoded private key
    public static PrivateKey buildPrivateKey(String base64)
    {
        // Remove the first and last lines if exists
        // Private key pem in PKCS8 format
        String privKeyPEM = base64.replace("-----BEGIN PRIVATE KEY-----", "");
        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
        System.out.println(privKeyPEM);

        // decode base64 string
        byte [] encoded = Base64.decode(privKeyPEM);

        // build PrivateKey
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encoded);
        PrivateKey privateKey = null;
        try {
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static PrivateKey buildSM2PrivateKey(String base64)
            throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        // Remove the first and last lines if exists
        // Private key pem in PKCS8 format
        String privKeyPEM = base64.replace("-----BEGIN PRIVATE KEY-----", "");
        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
        System.out.println(privKeyPEM);

        // decode base64 string
        byte [] encoded = Base64.decode(privKeyPEM);

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        return privateKey;
    }

    // Decode base64 encoded certificate
    public static X509Certificate buildSM2Cert(String base64) throws NoSuchProviderException {
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

    public static X509Certificate[] buildSM2Chain(String[] certs) throws NoSuchProviderException {
        System.out.println("certs.length = " + certs.length);
        X509Certificate[] chain = new X509Certificate[certs.length];
        for (int i=0; i<certs.length; ++i)
        {
            chain[i] = buildSM2Cert(certs[i]);
        }
        return chain;
    }
}
