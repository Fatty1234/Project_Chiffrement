package chiffrementclient;

import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import java.util.Scanner;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

@SuppressWarnings("unused")
public class SecureChatClient {
    private static final byte[] ivAndCipher = null;
	private String serverIp;
    private int serverPort;
    private String pseudonyme;
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private SecretKey aesKey;
    private PublicKey serverPublicKey;
    private volatile boolean running = true;

    public SecureChatClient(String serverIp, int serverPort, String pseudonyme) {
        this.serverIp = serverIp;
        this.serverPort = serverPort;
        this.pseudonyme = pseudonyme;
    }

    public void start() throws Exception {
        socket = new Socket(serverIp, serverPort);
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());

        int pubLen = in.readInt();
        byte[] pubBytes = new byte[pubLen];
        in.readFully(pubBytes);
        serverPublicKey = CryptoUtils.rebuildRSAPublicKey(pubBytes);

        aesKey = CryptoUtils.generateAESKey();
        byte[] aesRaw = aesKey.getEncoded();
        byte[] encAes = CryptoUtils.rsaEncrypt(aesRaw, serverPublicKey);

        out.writeUTF(pseudonyme);
        out.writeInt(encAes.length);
        out.write(encAes);
        out.flush();

        boolean ok = in.readBoolean();
        String welcome = in.readUTF();
        if (!ok) {
            System.err.println("Serveur a refusé la connexion : " + welcome);
            socket.close();
            return;
        }
        System.out.println("Connecté : " + welcome);

        Thread tListener = new Thread(this::listenLoop);
        tListener.start();

        Scanner sc = new Scanner(System.in, "UTF-8");
        while (running) {
            String line = sc.nextLine();
            if (line == null) break;
            if (line.trim().equalsIgnoreCase("/quit")) {
                sendPlainEncrypted("/quit");
                running = false;
                break;
            } else {
                String payload = pseudonyme + "::" + line;
                sendPlainEncrypted(payload);
            }
        }

        sc.close();
        cleanup();
    }

    private void listenLoop() {
        try {
            while (running) {
                int len = in.readInt();
                byte[] ivAndCipher = new byte[len];
                in.readFully(ivAndCipher);
                byte[] plain = CryptoUtils.aesDecrypt(ivAndCipher, aesKey);
                String msg = new String(plain, "UTF-8");
                // format: sender::text
                String[] parts = msg.split("::", 2);
                String from = parts.length > 0 ? parts[0] : "unknown";
                String text = parts.length > 1 ? parts[1] : "";
                System.out.println("[" + from + "] " + text);
            }
        } catch (Exception e) {
            if (running) System.err.println("Erreur lecture : " + e.getMessage());
        } finally {
            running = false;
            cleanup();
        }
    }

    private synchronized void sendPlainEncrypted(String payload) {
        try {
            byte[] plain = payload.getBytes("UTF-8");
            byte[] ivAndCipher = CryptoUtils.aesEncrypt(plain, aesKey);
            out.writeInt(ivAndCipher.length);
            out.write(ivAndCipher);
            out.flush();
        } catch (Exception e) {
            System.err.println("Erreur envoi: " + e.getMessage());
        }
    }

    private void cleanup() {
        try { socket.close(); } catch (IOException ignored) {}
        System.out.println("Déconnecté.");
    }

    public static void main(String[] args) throws Exception {
        @SuppressWarnings("resource")
		Scanner sc = new Scanner(System.in, "UTF-8");
        System.out.print("Adresse IP serveur (par défaut localhost): ");
        String ip = sc.nextLine().trim();
        if (ip.isEmpty()) ip = "localhost";
        System.out.print("Port serveur (par défaut 5555): ");
        String portS = sc.nextLine().trim();
        int port = 5555;
        if (!portS.isEmpty()) port = Integer.parseInt(portS);
        System.out.print("Ton pseudonyme: ");
        String pseudo = sc.nextLine().trim();
        if (pseudo.isEmpty()) {
            System.err.println("Pseudonyme requis.");
            return;
        }
        SecureChatClient client = new SecureChatClient(ip, port, pseudo);
        client.start();
    }
}