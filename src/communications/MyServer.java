package communications;

import java.net.*;
import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
import java.io.*;
import javax.security.cert.X509Certificate;
import java.security.KeyStore;

import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.logging.FileHandler;
import java.time.LocalTime;

import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicInteger;

public class MyServer implements Runnable {
  private static LocalTime time;
  private static Logger LOGGER = Logger.getLogger("Server");
  private static ServerSocket serverSocket;
  private static String type = "TLS";
  private static AtomicInteger connections = new AtomicInteger(0);

  public MyServer (ServerSocket socket) {
    this.serverSocket = socket;
    newListener();
  }

  private static void setupLogging() {
    try {
      LOGGER.addHandler(new FileHandler("./Log.html"));
    } catch(IOException e) {
      System.out.println(e.getMessage());
      e.printStackTrace();
    }
  }

  public static void main(String[] args) {
    setupLogging();
    System.out.println("Server is running.");
    int port = -1;
    if (args.length > 0) {
      port = Integer.parseInt(args[0]);
    }

    try {
      ServerSocketFactory socketFactory = getServerSocketFactory();
      ServerSocket socket = socketFactory.createServerSocket(port);
      ((SSLServerSocket) socket).setNeedClientAuth(true);
      new MyServer(socket);
    } catch(Exception e) {
      System.out.println("Unable to start: " + e.getMessage());
      e.printStackTrace();
    }
  }

  private void newListener() {
    new Thread(this).start();
  }

  public void run() {
    SSLSocket socket = acceptConnection();        // Blocking
    SSLSession session = socket.getSession();
    X509Certificate cert = verifyCertificateChain(session);
    String userID = cert.getSubjectDN().getName();
    connections.getAndIncrement();
    printCert(cert);
    LOGGER.log( Level.INFO, "Connection accepted", time.now() );

    try {
      PrintWriter sender = new PrintWriter(socket.getOutputStream(), true);
      BufferedReader receiver = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      String clientMsg = null;

      while ((clientMsg = receiver.readLine()) != null) {
        System.out.println(clientMsg);
        sender.println(clientMsg);
        sender.flush();
      }
      sender.close();
      receiver.close();
      socket.close();

    } catch(Exception e) {
      System.out.println("Session terminated by client.");
      e.printStackTrace();
    } finally {
      int nbr = connections.getAndDecrement()  - 1;
      System.out.println("Number of connections: " + nbr);
    }
  }

  private X509Certificate verifyCertificateChain(SSLSession session) {
    X509Certificate cert = null;
    try {
      cert = (X509Certificate) session.getPeerCertificateChain()[0];
    } catch(SSLPeerUnverifiedException e) {
      System.out.println("Peer's identity could not be verified");
      e.printStackTrace();
    }
    return cert;
  }

  private SSLSocket acceptConnection() {
    SSLSocket socket = null;
    try {
      socket = (SSLSocket) serverSocket.accept();
    } catch(Exception e) {
      System.out.println("Unable to establish socket. Shutting down.");
      e.printStackTrace();
    }
    newListener();
    return socket;
  }

  private static void printCert(X509Certificate cert) {
    String userID = cert.getSubjectDN().getName();
    String issuer = cert.getIssuerDN().getName();
    BigInteger serialNum = cert.getSerialNumber();
    System.out.println("communication.client connected");
    System.out.println("communication.client name (cert userID DN field): " + userID);
    System.out.println("communication.client name (cert issuer DN field): " + issuer);
    System.out.println("communication.client, x509 certificate serial number: " + serialNum);
    System.out.println(connections.get() + " concurrent connection(s)\n");
  }

  // set up key manager and authenticate.
  private static ServerSocketFactory getServerSocketFactory() {
    try {
      SSLContext context = SSLContext.getInstance("TLS");
      KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
      TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
      KeyStore keyStore = KeyStore.getInstance("JKS");
      KeyStore trustStore = KeyStore.getInstance("JKS");
      char[] password = "password".toCharArray();

      keyStore.load(new FileInputStream("./scripts/certs/serverkeystore"), password);
      trustStore.load(new FileInputStream("./scripts/certs/servertruststore"), password);
      kmf.init(keyStore, password);
      tmf.init(trustStore);
      context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
      ServerSocketFactory ssf = context.getServerSocketFactory();
      return ssf;
    } catch(Exception e) {
      e.printStackTrace();
    }
    return SSLServerSocketFactory.getDefault();
  }
}
