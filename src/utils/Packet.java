package utils;

import java.io.Serializable;

public class Packet implements Serializable{
    public byte[] message;
    public byte[] hash;
    public Packet(byte[] m, byte[] k){
        message = m;
        hash = k;
    }
}
