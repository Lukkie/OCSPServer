import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/**
 * Created by Lukas on 26-Mar-16.
 */
public class Databank {
    private ArrayList<BigInteger> revocations;

    private static Databank ourInstance = new Databank();
    public static Databank getInstance() {
        return ourInstance;
    }

    private Databank() {
        revocations = new ArrayList<BigInteger>();
    }

    public void addRevocation(BigInteger revoke) {
        revocations.add(revoke);
    }

    public boolean isRevoked(BigInteger revoke) {
        for (BigInteger bi: revocations) {
            if (bi.compareTo(revoke) == 0) return true;
        }
        return false;
    }

}
