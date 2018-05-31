package sm2;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

public class InspectSM2Cert {
    public static String cert = "MIIB1DCCAXoCCQC5q2njdtURBDAKBggqgRzPVQGDdTByMQswCQYDVQQGEwJDTjEL" +
            "MAkGA1UECAwCU0gxCzAJBgNVBAcMAnNoMQowCAYDVQQKDAFhMQowCAYDVQQLDAFi" +
            "MQwwCgYDVQQDDANMYW4xIzAhBgkqhkiG9w0BCQEWFGxpYW5nLnpob3VAZmExMjMu" +
            "Y29tMB4XDTE4MDUyMzAxMzY1MFoXDTI4MDUyMDAxMzY1MFowcjELMAkGA1UEBhMC" +
            "Q04xCzAJBgNVBAgMAlNIMQswCQYDVQQHDAJzaDEKMAgGA1UECgwBYTEKMAgGA1UE" +
            "CwwBYjEMMAoGA1UEAwwDTGFuMSMwIQYJKoZIhvcNAQkBFhRsaWFuZy56aG91QGZh" +
            "MTIzLmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAY9j5isnunZPvQkg75F" +
            "VdLz3WRg398QziAEe2+g9kjQZD3f2Eilrqsq5VCEuChTv0vXE2aDRbqtNlBOQgpX" +
            "rZQwCgYIKoEcz1UBg3UDSAAwRQIhAIT9oM42wWe+xieO9DSJBhBstIAsWV3G9Uih" +
            "caP6+pADAiA2uQx0zQ5pZ2fwYmuDMJVL2WhckJS3mJZMzszE6gN/4Q==";
    public static byte[] getCSPK(byte[] csCert)
    {
        InputStream inStream = new ByteArrayInputStream(csCert);
        ASN1Sequence seq = null;
        ASN1InputStream aIn;
        try
        {
            aIn = new ASN1InputStream(inStream);
            seq = (ASN1Sequence)aIn.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            SubjectPublicKeyInfo subjectPublicKeyInfo = cert.getSubjectPublicKeyInfo();
            AlgorithmIdentifier algSig = cert.getSignatureAlgorithm();

            System.out.println(algSig.getAlgorithm());
            DERBitString publicKeyData = subjectPublicKeyInfo.getPublicKeyData();
            byte[] publicKey = publicKeyData.getEncoded();
            System.out.println("publicKeyData.getEncoded():" + new String(Hex.encode(publicKey), "UTF-8"));
            byte[] encodedPublicKey = publicKey;
            byte[] eP = new byte[64];
            System.arraycopy(encodedPublicKey, 4, eP, 0, eP.length);
            return eP;
        }
        catch (Exception e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        byte[] certBytes = Base64.decode(cert);
        byte[] pubkey = getCSPK(certBytes);
        try {
            System.out.println(new String(Base64.encode(pubkey), "UTF-8"));
            System.out.println(new String(Hex.encode(pubkey), "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

    }
}
