import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.Security;

/**
 * Created by Lukas on 28-Mar-16.
 */
public class Main {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        int portNumber = 26262;
        IOThread ioThread = null;
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            System.out.println("Server listening on port "+portNumber);
            while (true) {
                ioThread = new IOThread(serverSocket.accept());
                ioThread.start();
            }
        } catch (IOException e) {
            System.err.println("Could not listen on port " + portNumber);
            System.exit(-1);
        }
    }
}
