package sm2;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import sun.java2d.loops.GeneralRenderer;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class GenKeyPairCert {
    private static String  SignAlgor = "1.2.156.10197.1.501";

    public static KeyPair genKeyPair() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair kp = keyGen.generateKeyPair();
        return kp;
    }

    private static X509Certificate generateCertificate(KeyPair keyPair) throws IOException, OperatorCreationException, CertificateException {

        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date from = new Date();
        Date to = new Date(from.getTime() + 365 * 86400000L);
        X500Name issuer = new X500Name("CN=zhouliang");
        X500Name subject = new X500Name("CN=zhouliangca");

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer, serialNumber, from, to, subject,
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SM3WITHSM2");
        ContentSigner signer = builder.build(keyPair.getPrivate());

        byte[] certBytes = certBuilder.build(signer).getEncoded();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));

    }

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        KeyPair kp = genKeyPair();
        PrivateKey sk = kp.getPrivate();
        PublicKey pk = kp.getPublic();

        System.out.println("private:" + new String(Base64.encode(sk.getEncoded()), "UTF-8"));
        System.out.println("public:" + new String(Base64.encode(pk.getEncoded()), "UTF-8"));

        try {
            X509Certificate cert = generateCertificate(kp);
            System.out.println("cert:" + new String(Base64.encode(cert.getEncoded()), "UTF-8"));
        } catch (IOException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }


    }
}
