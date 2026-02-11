import utils.AES_Simetric;
import utils.Hash;
import utils.Packet;
import utils.RSA_Asimetric;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Scanner;

public class Client {
    public static void main(String[] args) throws IOException {
        try (Socket socket = new Socket("localhost", 2222)) {

            System.out.println("[CLIENT] Conectado al servidor: " + socket.getInetAddress());

            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            oos.flush();
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            Certificate cert = (Certificate) ois.readObject();

            cert.verify(cert.getPublicKey());

            PublicKey publicKey = cert.getPublicKey();
            System.out.println("Certificado válido. Clave pública obtenida.");
            System.out.println("[CLIENT] Clave pública recibida OK.");

            SecretKey clauSimetrica = AES_Simetric.keygenKeyGeneration(128);
            String clauString = new String(clauSimetrica.getEncoded(), StandardCharsets.UTF_8);

            SecretKey hashSimetrica = Hash.passwordKeyGeneration(clauString, 128);
            String clauHash = new String(hashSimetrica.getEncoded(), StandardCharsets.UTF_8);

            Packet encryptedKeyPacket = new Packet(
                    RSA_Asimetric.encryptData(clauString.getBytes(StandardCharsets.UTF_8), publicKey),
                    RSA_Asimetric.encryptData(clauHash.getBytes(StandardCharsets.UTF_8), publicKey)
            );

            oos.writeObject(encryptedKeyPacket);
            oos.flush();

            Scanner scanner = new Scanner(System.in);

            while (true) {
                System.out.print("Escribe una palabra (adeu para salir): ");
                String word = scanner.nextLine();

                SecretKey hashWord = Hash.passwordKeyGeneration(word, 128);

                Packet wordPacket = new Packet(
                        AES_Simetric.encryptData(hashSimetrica, word.getBytes(StandardCharsets.UTF_8)),
                        AES_Simetric.encryptData(hashSimetrica, hashWord.getEncoded())
                );

                oos.writeObject(wordPacket);
                oos.flush();

                Packet ackPacket = (Packet) ois.readObject();

                byte[] ackBytes = AES_Simetric.decryptData(hashSimetrica, ackPacket.message);
                byte[] ackHashBytes = AES_Simetric.decryptData(hashSimetrica, ackPacket.hash);

                if (ackBytes == null || ackHashBytes == null) {
                    System.out.println("Error desencriptando ACK (clave incorrecta o datos corruptos).");
                    break;
                }

                String ack = new String(ackBytes, StandardCharsets.UTF_8);

                SecretKey ackHashClient = new SecretKeySpec(ackHashBytes, "AES");
                SecretKey ackHashServer = Hash.passwordKeyGeneration(ack, 128);

                if (Hash.compareHash(ackHashClient, ackHashServer)) {
                    System.out.println("ACK correcto recibido: " + ack);
                } else {
                    System.out.println("ACK modificado!");
                }

                if (word.equalsIgnoreCase("adeu")) {
                    break;
                }
            }
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }
}
