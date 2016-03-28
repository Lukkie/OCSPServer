import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


public class IOThread extends Thread {
    private Socket socket = null;
    private ObjectInputStream in = null;
    private ObjectOutputStream out = null;

    private ECPrivateKey ecPrivateKey;
    private ECPublicKey ecPublicKey;
    private byte[] sessionKey;
    private SecretKey secretKey = null;
    private X509Certificate certificate;

    public IOThread(Socket socket) {
        super("IOThread");
        System.out.println("IOThread started");
        this.socket = socket;
        sessionKey = null;
        Security.addProvider(new BouncyCastleProvider());

    }


    @Override
    public void run() {
        try {
            in = new ObjectInputStream(this.socket.getInputStream());
            out = new ObjectOutputStream(this.socket.getOutputStream());
            System.out.println("Waiting for requests.");
            String request;
            while ((request = (String)in.readObject()) != null) {
                processInput(request, in, out);

            }
            System.out.println("Stopping run method");
        }
        catch (IOException e) {
            try {
                in.close();
                out.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            System.out.println("Connection lost, shutting down thread.");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

    }


    private boolean processInput(String request, ObjectInputStream in,
                                 ObjectOutputStream out)  {
        System.out.println("Processing request: \""+request+"\"");
        try {
            switch (request) {


                case "isCertificateRevoked": {
                    isCertificateRevoked(in, out);
                    break;
                }

                case "revoke": {
                    revoke(in, out);
                    break;
                }


                //Test cases
                case "getSessionKey": {
                    out.writeObject(secretKey);
                    break;
                }


                default: {
                    System.out.println("Request not recognized. Stopping connection ");
                    return false;
                }
            }
        }catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return true;

    }

    private X509Certificate loadCertificate(ObjectInputStream in, ObjectOutputStream out, boolean encrypted) throws IOException, ClassNotFoundException {
        byte[] certificateByteArray = (byte[]) in.readObject();
        if (encrypted) certificateByteArray = Arrays.copyOfRange(Tools.decrypt(certificateByteArray, secretKey),0,413);
        X509Certificate certificate = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream byteInputStream = new ByteArrayInputStream(certificateByteArray);
            certificate = (X509Certificate)certFactory.generateCertificate(byteInputStream);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return certificate;
    }

    private void revoke(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException {
        // Certificaat inlezen
        X509Certificate cert = loadCertificate(in, out, true);
        Databank.getInstance().addRevocation(cert.getSerialNumber());

    }

    private void isCertificateRevoked(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException {
        // Kijken wie vraagt
        String requester = (String)in.readObject();

        // Certificaat inlezen
        X509Certificate cert = loadCertificate(in, out, false);
        boolean isRevoked = Databank.getInstance().isRevoked(cert.getSerialNumber());
        byte[] answer = new byte[1];
        answer[0] = (isRevoked? (byte)0x00 : (byte)0x01);

        // Aan de hand van requester: RSA of AES
        if (requester.equals("LCP") || requester.equals("Shop")) { // AES
            setupSecureConnection(in, out);
            out.writeObject(Tools.encryptMessage(Tools.applyPadding(answer), secretKey));
        }
        else if (requester.equals("Middleware")) { // RSA
            try {
                PublicKey publicKey = Tools.getPublicRSAKeyFromBytes(Tools.pubKeyMW);
                byte[] toBeSent = Crypto.encryptWithPublicKeyRSA(answer, publicKey);
                out.writeObject(toBeSent);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        else { // Error
            new Exception("Requester not recognized.").printStackTrace();
        }

    }


    private void setupSecureConnection(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException {

        // genereer nieuw EC keypair
        // Niet nodig
        /*CreateStaticKeyPairs.KeyObject keyObject = CreateStaticKeyPairs.createStaticKeyPairs();
        ecPublicKey = (ECPublicKey)keyObject.publicKey;
        ecPrivateKey = (ECPrivateKey)keyObject.privateKey;
        certificate = keyObject.certificate;*/

        out.writeObject(Tools.ECCertificate);


        // Lees certificaat van andere partij in, check of juist en lees public key
        X509Certificate certificateOtherParty = loadCertificate(in, out, false);
        PublicKey publicKeyOtherParty = certificateOtherParty.getPublicKey();

        sessionKey = generateSessionKey(publicKeyOtherParty.getEncoded());
        /*System.out.println("Received W (Public Key other party) (length: "+
                ecPublicKeyOtherPartyBytes.length+" byte): "+
                new BigInteger(1, ecPublicKeyOtherPartyBytes).toString(16));*/



        secretKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");
        System.out.print("SecretKey: ");
        Tools.printByteArray(secretKey.getEncoded());


    }

    private byte[] generateSessionKey(byte[] pubKeyOtherPartyBytes) {
        try {
            PublicKey pubKeyOtherParty = KeyFactory.getInstance("ECDH", "BC")
                    .generatePublic(new X509EncodedKeySpec(pubKeyOtherPartyBytes));
            KeyAgreement keyAgr;
            keyAgr = KeyAgreement.getInstance("ECDH", "BC");
            keyAgr.init(Tools.getECPrivateKey());


            keyAgr.doPhase(pubKeyOtherParty, true);
            MessageDigest hash = MessageDigest.getInstance("SHA-1");
            byte[] secret = keyAgr.generateSecret();
            System.out.print("Secret key (length: "+secret.length+"):\t");
            Tools.printByteArray(secret);
            System.out.println();
            byte[] sessionKey = hash.digest(secret);
            sessionKey = Arrays.copyOf(sessionKey, 16);
            System.out.print("Hashed secret key (length: "+sessionKey.length+"):\t");
            Tools.printByteArray(sessionKey);

            return sessionKey;
        }
        catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }



}
