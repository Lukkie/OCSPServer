import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/**
 * Created by Lukas on 26-Mar-16.
 */
public class Databank {
    private ArrayList<X509Certificate> revocations;

    private static Databank ourInstance = new Databank();
    public static Databank getInstance() {
        return ourInstance;
    }

    private Databank() {
        revocations = new ArrayList<X509Certificate>();
    }

    /*
    public void addRevocation(X509Certificate cert) {
        revocations.add(cert.getSerialNumber());
    }

    public boolean isRevoked(X509Certificate cert) {
        System.out.println("Is revoked? "+cert.getSerialNumber());
        for (BigInteger bi: revocations) {
            System.out.println("Compared to: "+bi.toString());
            if (bi.compareTo(cert.getSerialNumber()) == 0) return true;
        }
        return false;
    }*/

    public void addRevocation(X509Certificate cert) {
        revocations.add(cert);

    }



    public boolean isRevoked(X509Certificate cert) {
//        try {
            //System.out.print("Checking cert: ");
            //Tools.printByteArray(cert.getEncoded());
            for (X509Certificate bi : revocations) {

                //System.out.print("Checking with DB entry: ");
                //Tools.printByteArray(bi.getEncoded());
                if (bi.equals(cert)) return true;
            }

//        }
//        catch (CertificateEncodingException e) {
//            e.printStackTrace();
//        }
        return false;
    }

}
