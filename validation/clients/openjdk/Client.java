import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "client", version = "client 1.0")
public class Client implements Runnable {

    //@Option(names = {"--check_crl"})
    //boolean checkCrl;

    //@Option(names = {"--check_ocsp"})
    //boolean checkOcsp;

    //@Option(names = {"--check_ocsp_staple"})
    //boolean checkOcspStaple;

    @Option(names = {"--host"})
    String host = "";

    @Option(names = {"--port"})
    int port;

    @Option(names = {"--trust_anchor"})
    String trustAnchor = "";

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Client()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public void run() {
        SSLContext ctx = null;
        try {
            ctx = SSLContext.getInstance("TLSv1.3");
        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.toString());
            System.exit(1);
        }

        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            System.err.println(e.toString());
            System.exit(1);
        }

        FileInputStream fis = null;
        try {
            fis = new FileInputStream(trustAnchor);
        } catch (FileNotFoundException e) {
            System.err.println(e.toString());
            System.exit(1);
        }
        X509Certificate caCert = null;
        try {
            caCert = (X509Certificate) cf.generateCertificate(fis);
        } catch (CertificateException e) {
            System.err.println(e.toString());
            System.exit(1);
        }
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            System.err.println(e.toString());
            System.exit(1);
        }
        try {
            ks.load(null, null);
        } catch (Exception e) {
            System.err.println(e.toString());
            System.exit(1);
        }
        try {
            ks.setCertificateEntry("RootCA", caCert);
        } catch (KeyStoreException e) {
            System.err.println(e.toString());
            System.exit(1);
        }
        TrustManagerFactory tmf = null;
        try {
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.toString());
            System.exit(1);
        }
        try {
            tmf.init(ks);
        } catch (KeyStoreException e) {
            System.err.println(e.toString());
            System.exit(1);
        }

        try {
            ctx.init(null, tmf.getTrustManagers(),null);
        } catch (KeyManagementException e) {
            System.err.println(e.toString());
            System.exit(1);
        }

        SSLParameters params = ctx.getDefaultSSLParameters();
        // adjust the parameters to be secure
        params.setEndpointIdentificationAlgorithm("HTTPS");

        SSLSocket socket = null;
        try {
            socket = (SSLSocket) ctx.getSocketFactory().createSocket(host, port);
        } catch (IOException e) {
            System.err.println(e.toString());
            System.exit(1);
        }
        try {
            socket.setTcpNoDelay(true);
        } catch (SocketException e) {
            System.err.println(e.toString());
            System.exit(1);
        }
        socket.setSSLParameters(params);
        try {
            socket.startHandshake();
        } catch (Exception e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }
}
