import java.io.*;
import java.net.Socket;
import java.security.KeyPair;

public class FilServer implements Runnable {
    private Socket servidor;
    private KeyPair keys;
    public FilServer(Socket servidor, KeyPair keys) throws IOException {
        this.servidor = servidor;
        this.keys = keys;
    }

    @Override
    public void run(){
        try (BufferedReader in = new BufferedReader(new InputStreamReader(servidor.getInputStream()));
             BufferedWriter out = new BufferedWriter(new OutputStreamWriter(servidor.getOutputStream()));
             ObjectInputStream ois = new ObjectInputStream(servidor.getInputStream());
             ObjectOutputStream oos = new ObjectOutputStream(servidor.getOutputStream())) {

            oos.writeObject(keys.getPublic());


        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
