package sm2;

import com.itextpdf.text.error_messages.MessageLocalization;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;

public class InspectPDFcms {
    public static String printP7fromFile(String path) throws IOException {
        // get p7 string from android pdf
        String base64P7 = null;
        System.out.println(path);
        PdfReader reader = new PdfReader(path);
        AcroFields fields = reader.getAcroFields();

        ArrayList<String> names = fields.getSignatureNames();
        for (String name : names) {
            System.out.println("===== " + name + " =====");
            Security.addProvider(new BouncyCastleProvider());
            System.out.println("Signature covers whole document: "
                    + fields.signatureCoversWholeDocument(name));
            System.out.println("Document revision: " + fields.getRevision(name)
                    + " of " + fields.getTotalRevisions());

            PdfDictionary v = fields.getSignatureDictionary(name);
            if (v == null)
                return null;
            PdfName sub = v.getAsName(PdfName.SUBFILTER);
            PdfString contents = v.getAsString(PdfName.CONTENTS);
            PdfPKCS7 pk = null;

            byte[] array = contents.getOriginalBytes();
            base64P7 = new String(Base64.encode(array), "UTF-8");
            System.out.println(base64P7);
            System.out.println(new String(Hex.encode(array), "UTF-8"));

            ASN1Primitive pkcs;
            ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(array));
            pkcs = din.readObject();

            System.out.println(pkcs instanceof ASN1Sequence);

            ASN1Sequence signedData = (ASN1Sequence)pkcs;
            ASN1ObjectIdentifier objId = (ASN1ObjectIdentifier)signedData.getObjectAt(0);
            System.out.println(objId.getId());
            //return base64P7;
        }
        return base64P7;
    }

    public static void main(String[] args) {
        try {
            String p7 = printP7fromFile("testsm2.pdf");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
