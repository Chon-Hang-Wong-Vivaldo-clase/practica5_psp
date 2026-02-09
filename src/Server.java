import utils.RSA_Asimetric;

import javax.imageio.IIOException;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.KeyPair;

public class Server {
    public static void main(String[] args) throws IOException {
        ServerSocket servidor = new ServerSocket(2222);
        KeyPair clausServer = RSA_Asimetric.randomGenerate(128);

        try {
            while (true) {
                new Thread(new FilServer(servidor.accept(),clausServer)).start();
            }
        }catch (IIOException e){}
    }
}
