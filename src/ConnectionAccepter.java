import java.io.IOException;
import java.net.ServerSocket;

/**
 * Created by Lukas on 07-Apr-16.
 */
public class ConnectionAccepter extends Thread {

    @Override
    public void run() {
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
