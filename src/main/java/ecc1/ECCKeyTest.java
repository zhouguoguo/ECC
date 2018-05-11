package ecc1;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class ECCKeyTest {
    public static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final char ENCODED_ZERO = ALPHABET[0];

    public static KeyPair KeyPairGeneration(BigInteger q, BigInteger a, BigInteger b, String G, BigInteger n)
            throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        ECCurve curve = new ECCurve.Fp(q, a, b);

        ECParameterSpec ecSpec = new ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode(G)), // G
                n); // n

        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair pair = g.generateKeyPair();
        return pair;
    }

    public static String hash256(String data) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String re;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        //md.update(Hex.decode(data));
        //md.update(data.getBytes("UTF-8"));
        md.update(Hex.decode(data));
        byte[] digest = md.digest();
        return new String(Hex.encode(digest), "UTF-8");
    }

    public static String RipeMD160(String data) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String re;
        MessageDigest md = MessageDigest.getInstance("RipeMD160");
        //md.update(Hex.decode(data));
        //md.update(data.getBytes("UTF-8"));
        md.update(Hex.decode(data));
        byte[] digest = md.digest();
        return new String(Hex.encode(digest), "UTF-8");
    }

    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        // this is just long division which accounts for the base of the input digits
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }

    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        // Count leading zeros.
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            ++zeros;
        }
        // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
        input = Arrays.copyOf(input, input.length); // since we modify it in-place
        char[] encoded = new char[input.length * 2]; // upper bound
        int outputStart = encoded.length;
        for (int inputStart = zeros; inputStart < input.length; ) {
            encoded[--outputStart] = ALPHABET[divmod(input, inputStart, 256, 58)];
            if (input[inputStart] == 0) {
                ++inputStart; // optimization - skip leading zeros
            }
        }
        // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
        while (outputStart < encoded.length && encoded[outputStart] == ENCODED_ZERO) {
            ++outputStart;
        }
        while (--zeros >= 0) {
            encoded[--outputStart] = ENCODED_ZERO;
        }
        // Return encoded string (including encoded leading zeros).
        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    public static void main(String[] args){

        try {
            for (int i=1; i <= 20; i++)
                getAddress(i);

        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    private static void getAddress(int i)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException
    {
        //Key Pair Generation
        //From Explicit Parameters
//        ECCurve curve = new ECCurve.Fp(
//                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16), // q
//                BigInteger.valueOf(0), // a
//                BigInteger.valueOf(7)); // b
//        ECParameterSpec ecSpec = new ECParameterSpec(
//                curve,
//                curve.decodePoint(Hex.decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")), // G
//                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)); // n

//        String s1 = "64883860557948295243596034287815708466328308378440624460499082508371612159443"; // 16进制数
//        BigInteger b = new BigInteger(s1);           // 16进制转成大数类型
//        String s2 = b.toString(16);
//        System.out.println("s2: "+ s2);

        // from named curves
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

        ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(
                BigInteger.valueOf(i), // d
                ecSpec);

        System.out.println("priKeySpec.getD():" + priKeySpec.getD());

        // calc the K by priKey using curve
        ECPoint K = ecSpec.getG().multiply(BigInteger.valueOf(i));
        //ECPoint K = ecSpec.getG();
        // Unsuppressed public key K
        String UhexPointK = new String(Hex.encode(K.getEncoded(false)), "UTF-8");
        System.out.println("Unsuppressed Calculated public key: " + UhexPointK);
        // Suppressed public key K
        String ShexPointK = new String(Hex.encode(K.getEncoded(true)), "UTF-8");
        System.out.println("Suppressed Calculated public key: " + ShexPointK);
        // end

        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(
                K, // K
                ecSpec);

        Security.addProvider(new BouncyCastleProvider());
        KeyFactory fact = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey sk = fact.generatePrivate(priKeySpec);
        PublicKey pk = fact.generatePublic(pubKeySpec);

//        String Kx = K.getXCoord().toBigInteger().toString(16);
//        String Ky = K.getYCoord().toBigInteger().toString(16);
//
//        System.out.println("x coord: " + Kx);
//        System.out.println("y coord: " + Ky);

        String Kx = new String(Hex.encode(K.getXCoord().getEncoded()));
        String Ky = new String(Hex.encode(K.getYCoord().getEncoded()));

        System.out.println("x coord: " + Kx);
        System.out.println("y coord: " + Ky);

        // 1. calc sha256
        String testPK = hash256(UhexPointK);
        System.out.println("after sha256:" + testPK);

        // 2. calc RipeMD160
        testPK = RipeMD160(testPK);
        System.out.println("after RipeMD160:" + testPK);

        //testPK = "0b14f003d63ab31aef5fedde2b504699547dd1f6";
        // 3. add 00 at beginning
        testPK = "00" + testPK;
        System.out.println("after add 00:" + testPK);

        // 4. sha256 twice
        String checkSum = hash256(testPK);
        checkSum = hash256(checkSum);
        System.out.println("after sha256 twice:" + checkSum);

        // 5. add first 8 bits as checkSum to the end of testPK
        testPK = testPK + checkSum.substring(0, 8);
        System.out.println("after adding checksum:" + testPK);

        // 6. base58
        String address = encode(Hex.decode(testPK));
        System.out.println("--------bitcoin address:" + address);
//        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
//        g.initialize(ecSpec, new SecureRandom());
//        KeyPair pair = g.generateKeyPair();
//
//        KeyFactory fact = KeyFactory.getInstance("ECDSA", "BC");
//        PublicKey pk = fact.generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()));
//        PrivateKey sk = fact.generatePrivate(new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded()));

    }
}
