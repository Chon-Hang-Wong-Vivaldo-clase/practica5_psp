import java.io.FileInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public class Server {
    public static void main(String[] args) throws Exception {

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("servidor.jks"), "123456".toCharArray());

        PrivateKey privateKey = (PrivateKey) ks.getKey("servidor", "123456".toCharArray());
        Certificate cert = ks.getCertificate("servidor");

        System.out.println("[SERVER] JKS cargado. Certificado listo.");

        ServerSocket serverSocket = new ServerSocket(2222);
        System.out.println("[SERVER] Escuchando en 2222...");

        while (true) {
            Socket client = serverSocket.accept();
            System.out.println("[SERVER] Cliente conectado: " + client.getInetAddress());

            new Thread(new FilServer(client, cert, privateKey)).start();
        }
    }
}
