package chiffrement;

import java.io.*;
import java.net.Socket;
import javax.crypto.SecretKey;
import java.util.Date;

public class ClientHandler implements Runnable {
    private Socket socket;
    private String pseudonyme;
    private SecretKey aesKey;
    private SecureChatServer server;
    private DataInputStream in;
    private DataOutputStream out;
    private volatile boolean running = true;

    public ClientHandler(Socket socket, String pseudonyme, SecretKey aesKey, SecureChatServer server, DataInputStream in, DataOutputStream out) {
        this.socket = socket;
        this.pseudonyme = pseudonyme;
        this.aesKey = aesKey;
        this.server = server;
        this.in = in;
        this.out = out;
    }

    @Override
    public void run() {
        try {
            while (running) {
                int len;
                try {
                    len = in.readInt();
                } catch (EOFException eof) {
                    break;
                }
                byte[] ivAndCipher = new byte[len];
                in.readFully(ivAndCipher);

                byte[] plain = CryptoUtils.aesDecrypt(ivAndCipher, aesKey);
                String message = new String(plain, "UTF-8");

                if (message.equals("/quit")) {
                    running = false;
                    break;
                }

                String[] parts = message.split("::", 2);
                String from = parts.length > 0 ? parts[0] : pseudonyme;
                String text = parts.length > 1 ? parts[1] : "";

                System.out.println("[" + new Date() + "] " + from + " -> " + text);

                server.broadcast(from, text);
            }
        } catch (Exception e) {
            System.err.println("Erreur Handler " + pseudonyme + " : " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    public synchronized void sendPlainAndEncrypt(String plainText) {
        try {
            byte[] plain = plainText.getBytes("UTF-8");
            byte[] ivAndCipher = CryptoUtils.aesEncrypt(plain, aesKey);
            out.writeInt(ivAndCipher.length);
            out.write(ivAndCipher);
            out.flush();
        } catch (Exception e) {
            System.err.println("Erreur envoi vers " + pseudonyme + " : " + e.getMessage());
        }
    }

    private void cleanup() {
        try { socket.close(); } catch (IOException ignored) {}
        server.removeClient(pseudonyme);
    }
}
