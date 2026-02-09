import utils.AES_Simetric;
import utils.Hash;
import utils.RSA_Asimetric;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Scanner;

public class Client {
    public static void main(String[] args) throws IOException {
        try (Socket socket = new Socket("localhost", 2222);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             Scanner input = new Scanner(System.in);
        ){
            SecretKey clauSimetrica = AES_Simetric.keygenKeyGeneration(128);
            String clauString = new String(clauSimetrica.getEncoded(), StandardCharsets.UTF_8);
            SecretKey hashSimetrica = Hash.passwordKeyGeneration(clauString, 128);

            PublicKey publicKey = ois.;
            RSA_Asimetric.encryptData(clauString.getBytes(), ois.readObject());

        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
