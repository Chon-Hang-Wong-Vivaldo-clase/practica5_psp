import utils.AES_Simetric;
import utils.Hash;
import utils.Packet;
import utils.RSA_Asimetric;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public class FilServer implements Runnable {
    private final Socket servidor;
    private final Certificate cert;
    private final PrivateKey privateKey;

    public FilServer(Socket servidor, Certificate cert, PrivateKey privateKey) {
        this.servidor = servidor;
        this.cert = cert;
        this.privateKey = privateKey;
    }


    @Override
    public void run() {
        try (ObjectOutputStream oos = new ObjectOutputStream(servidor.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(servidor.getInputStream())) {

            oos.writeObject(cert);
            oos.flush();
            System.out.println("Se ha enviado la clave pública!");

            Packet encryptedKeyPacket = (Packet) ois.readObject();
            byte[] clauStringBytes = RSA_Asimetric.decryptData(encryptedKeyPacket.message, privateKey);
            byte[] clauHashBytes   = RSA_Asimetric.decryptData(encryptedKeyPacket.hash, privateKey);

            String clauString = new String(clauStringBytes, StandardCharsets.UTF_8);
            String clauHash   = new String(clauHashBytes, StandardCharsets.UTF_8);

            SecretKey hashServer = Hash.passwordKeyGeneration(clauString, 128);

            SecretKey hashClient = new SecretKeySpec(clauHash.getBytes(StandardCharsets.UTF_8), "AES");

            if (!Hash.compareHash(hashClient, hashServer)) {
                System.out.println("El Hash del mensaje es diferente, el mensaje ha sido modificado.");
                return;
            }
            System.out.println("Hash válido.");

            SecretKey clauCompartida = hashServer;

            while (true) {
                Packet p = (Packet) ois.readObject();

                byte[] wordBytes = AES_Simetric.decryptData(clauCompartida, p.message);
                byte[] hashBytes = AES_Simetric.decryptData(clauCompartida, p.hash);

                if (wordBytes == null || hashBytes == null) {
                    System.out.println("Error desencriptando (clave incorrecta o datos corruptos).");
                    break;
                }

                String word = new String(wordBytes, StandardCharsets.UTF_8);

                SecretKey hashClientMsg = new SecretKeySpec(hashBytes, "AES");
                SecretKey hashServerMsg = Hash.passwordKeyGeneration(word, 128);

                if (!Hash.compareHash(hashClientMsg, hashServerMsg)) {
                    System.out.println("El hash del mensaje no coincide.");
                } else {
                    System.out.println("Paraula rebuda: " + word);
                }

                String acuse = "DataRecived";
                SecretKey acuseHashKey = Hash.passwordKeyGeneration(acuse, 128);

                Packet acusePacket = new Packet(
                        AES_Simetric.encryptData(clauCompartida, acuse.getBytes(StandardCharsets.UTF_8)),
                        AES_Simetric.encryptData(clauCompartida, acuseHashKey.getEncoded())
                );
                oos.writeObject(acusePacket);
                oos.flush();
                if ("adeu".equalsIgnoreCase(word)) break;
            }

        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
