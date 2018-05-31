package sm2;

import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;


public class VerifySignature {

    static final String DIGEST_SHA1 = "SHA1withRSA";
    static final String BC_PROVIDER = "BC";

    public static void main(String[] args) throws Exception {
        String text = "This is a message";

        System.out.println(new String(Base64.encode(text.getBytes("UTF-8")), "UTF-8"));

        String envelopedData = "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAQAAoIAwggLQMIIC" +
                "OQIEQ479uzANBgkqhkiG9w0BAQUFADCBrjEmMCQGCSqGSIb3DQEJARYXcm9zZXR0YW5ldEBtZW5k" +
                "ZWxzb24uZGUxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIEwZCZXJsaW4xDzANBgNVBAcTBkJlcmxpbjEi" +
                "MCAGA1UEChMZbWVuZGVsc29uLWUtY29tbWVyY2UgR21iSDEiMCAGA1UECxMZbWVuZGVsc29uLWUt" +
                "Y29tbWVyY2UgR21iSDENMAsGA1UEAxMEbWVuZDAeFw0wNTEyMDExMzQyMTlaFw0xOTA4MTAxMzQy" +
                "MTlaMIGuMSYwJAYJKoZIhvcNAQkBFhdyb3NldHRhbmV0QG1lbmRlbHNvbi5kZTELMAkGA1UEBhMC" +
                "REUxDzANBgNVBAgTBkJlcmxpbjEPMA0GA1UEBxMGQmVybGluMSIwIAYDVQQKExltZW5kZWxzb24t" +
                "ZS1jb21tZXJjZSBHbWJIMSIwIAYDVQQLExltZW5kZWxzb24tZS1jb21tZXJjZSBHbWJIMQ0wCwYD" +
                "VQQDEwRtZW5kMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+X1g6JvbdwJI6mQMNT41GcycH" +
                "UbwCFWKJ4qHDaHffz3n4h+uQJJoQvc8yLTCfnl109GB0yL2Y5YQtTohOS9IwyyMWBhh77WJtCN8r" +
                "dOfD2DW17877te+NlpugRvg6eOH6np9Vn3RZODVxxTyyJ8pI8VMnn13YeyMMw7VVaEO5hQIDAQAB" +
                "MA0GCSqGSIb3DQEBBQUAA4GBALwOIc/rWMAANdEh/GgO/DSkVMwxM5UBr3TkYbLU/5jg0Lwj3Y++" +
                "KhumYSrxnYewSLqK+JXA4Os9NJ+b3eZRZnnYQ9eKeUZgdE/QP9XE04y8WL6ZHLB4sDnmsgVaTU+p" +
                "0lFyH0Te9NyPBG0J88109CXKdXCTSN5gq0S1CfYn0staAAAxggG9MIIBuQIBATCBtzCBrjEmMCQG" +
                "CSqGSIb3DQEJARYXcm9zZXR0YW5ldEBtZW5kZWxzb24uZGUxCzAJBgNVBAYTAkRFMQ8wDQYDVQQI" +
                "EwZCZXJsaW4xDzANBgNVBAcTBkJlcmxpbjEiMCAGA1UEChMZbWVuZGVsc29uLWUtY29tbWVyY2Ug" +
                "R21iSDEiMCAGA1UECxMZbWVuZGVsc29uLWUtY29tbWVyY2UgR21iSDENMAsGA1UEAxMEbWVuZAIE" +
                "Q479uzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUx" +
                "DxcNMTMwNTIxMDE1MDUzWjAjBgkqhkiG9w0BCQQxFgQU8mE6gw6iudxLUc9379lWK0lUSWcwDQYJ" +
                "KoZIhvcNAQEBBQAEgYB5mVhqJu1iX9nUqfqk7hTYJb1lR/hQiCaxruEuInkuVTglYuyzivZjAR54" +
                "zx7Cfm5lkcRyyxQ35ztqoq/V5JzBa+dYkisKcHGptJX3CbmmDIa1s65mEye4eLS4MTBvXCNCUTb9" +
                "STYSWvr4VPenN80mbpqSS6JpVxjM0gF3QTAhHwAAAAAAAA==";
        String Sig_Bytes ="YduK22AlMLSXV3ajX5r/pX5OQ0xjj58uhGT9I9MvOrz912xNHo+9OiOKeMOD+Ys2/LUW3XaN6T+/"+
                "tuRM5bi4RK7yjaqaJCZWtr/O4I968BQGgt0cyNvK8u0Jagbr9MYk6G7nnejbRXYHyAOaunqD05lW"+
                "U/+g92i18dl0OMc50m4=";

        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        CMSSignedData signedData = null;

        CMSProcessable cmsProcesableContent = new CMSProcessableByteArray(Base64.decode(Sig_Bytes.getBytes()));
        signedData = new CMSSignedData(cmsProcesableContent, Base64.decode(envelopedData.getBytes()));
        // Verify signature
        Store store = signedData.getCertificates();
        SignerInformationStore signers = signedData.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            Collection certCollection = store.getMatches(signer.getSID());
            Iterator certIt = certCollection.iterator();
            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
            X509Certificate certFromSignedData = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(certHolder);
            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC_PROVIDER).build(certFromSignedData))) {
                System.out.println("Signature verified");
            } else {
                System.out.println("Signature verification failed");
            }
        }
    }



}