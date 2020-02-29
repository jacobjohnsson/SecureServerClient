package communications;

import java.net.*;
import java.io.*;
import javax.net.ssl.*;
import javax.security.cert.X509Certificate;
import java.security.KeyStore;
import java.security.cert.*;
import java.math.BigInteger;
import java.util.Scanner;

public class MyClient {
  private static String host = null;
  private static int port = -1;

  public static void main(String[] args) {
    try {
      setup(args);
    } catch(Exception e) {
      e.printStackTrace();
    }
  }

  public static void setup(String[] args) throws Exception {
    handleInput(args);
    KeyStore ks = KeyStore.getInstance("JKS");
    KeyStore ts = KeyStore.getInstance("JKS");
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
    SSLContext context = SSLContext.getInstance("TLS");

    char[] password = authenticateUser(ks, ts);

    kmf.init(ks, password);
    tmf.init(ts);
    context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    SSLSocketFactory factory = context.getSocketFactory();


    SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
    System.out.println("\nSocket before handshake: \n" + socket + "\n");

    String subject = "";
    try {

      socket.startHandshake();

      SSLSession session = socket.getSession();
      X509Certificate cert = (javax.security.cert.X509Certificate)session.getPeerCertificateChain()[0];
      subject = cert.getSubjectDN().getName();
      String issuer = cert.getIssuerDN().getName();
      BigInteger serialNum = cert.getSerialNumber();
      System.out.println("certificate name (subject DN field) on certificate received from communication.server:\n" + subject + "\n");
      System.out.println("communication.server name (cert issuer DN field): " + issuer);
      System.out.println("communication.server, x509 certificate serial number: " + serialNum);
      System.out.println("socket after handshake:\n" + socket + "\n");
      System.out.println("secure connection established\n\n");
      System.out.println("Server is awaiting your message.");

    } catch(Exception e) {
      throw new IOException(e.getMessage());
    }

    // Let the communications begin!
    try {
      communicate(socket, subject);
    } catch(IOException e) {
      System.out.println("Unexpected IOException!");
      e.printStackTrace();
    }
  }

  private static void communicate(Socket socket, String subject) throws IOException {
    PrintWriter sender = new PrintWriter(socket.getOutputStream(), true);
    BufferedReader receiver = new BufferedReader(new InputStreamReader(socket.getInputStream()));

    communicate(sender, receiver, subject);

    sender.close();
    receiver.close();
    socket.close();
  }

  private static void communicate(PrintWriter sender, BufferedReader receiver, String subject) throws IOException {
    BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
    String msg = userInput.readLine();

    if (msg.toLowerCase().equals("quit")) {
      return;
    }

    sender.println(msg);
    System.out.println("Message sent");

    System.out.println("Received: \n" + receiver.readLine());
    communicate(sender, receiver, subject);
  }

  private static char[] authenticateUser(KeyStore keyStore, KeyStore trustStore) {
    boolean userAuthenticated = false;
    char[] password = null;
    while (!userAuthenticated) {

      password = readPassword();

      try {
        keyStore.load(new FileInputStream("./scripts/certs/clientkeystore"), password);
        trustStore.load(new FileInputStream("./scripts/certs/clienttruststore"), password);
        userAuthenticated = true;
      } catch(Exception e) {
        System.out.println("Invalid password, try again: ");
      }
    }
    return password;
  }

  private static char[] readPassword() {
    System.out.println("Enter keystore password: ");
    return System.console().readPassword();
  }

  private static void handleInput(String[] args) {
    if (args.length < 2) {
      System.out.println("args should be \'localhost 9876\'");
      return;
    }
    host = args[0];
    try {
      port = Integer.parseInt(args[1]);
    } catch(IllegalArgumentException e) {
      System.out.println("port must be an integer.");
      return;
    }
  }

}
