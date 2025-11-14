package chiffrement;

import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

public class SecureChatServer {
    private int port;
    private KeyPair rsaKeyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private Map<String, ClientHandler> clients = new ConcurrentHashMap<>();
    
    private File logFile = new File("server_messages.log");
    private BufferedWriter logWriter;

    public SecureChatServer(int port) {
        this.port = port;
    }

    public void start() throws Exception {
        rsaKeyPair = CryptoUtils.generateRSAKeyPair();
        privateKey = rsaKeyPair.getPrivate();
        publicKey = rsaKeyPair.getPublic();

        if (!logFile.exists()) logFile.createNewFile();
        logWriter = new BufferedWriter(new FileWriter(logFile, true));

        try (ServerSocket serverSocket = new ServerSocket(port)) {
			System.out.println("SecureChatServer démarré sur le port " + port);
			System.out.println("RSA public key (base64) : " + CryptoUtils.toBase64(publicKey.getEncoded()));

			while (true) {
			    Socket socket = serverSocket.accept();
			    System.out.println("Connexion entrante : " + socket.getRemoteSocketAddress());

			    new Thread(() -> {
			        try {
			            handleInitial(socket);
			        } catch (Exception e) {
			            System.err.println("Erreur handshake: " + e.getMessage());
			            try { socket.close(); } catch (IOException ignored) {}
			        }
			    }).start();
			}
		}
    }

    private void handleInitial(Socket socket) throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        byte[] pubBytes = publicKey.getEncoded();
        out.writeInt(pubBytes.length);
        out.write(pubBytes);
        out.flush();

        String pseudonyme = in.readUTF();
        int encKeyLen = in.readInt();
        byte[] encKeyBytes = new byte[encKeyLen];
        in.readFully(encKeyBytes);

        byte[] aesRaw = CryptoUtils.rsaDecrypt(encKeyBytes, privateKey);
        SecretKey aesKey = CryptoUtils.rebuildAESKey(aesRaw);

        synchronized (clients) {
            if (clients.containsKey(pseudonyme)) {
                out.writeBoolean(false);
                out.writeUTF("Pseudonyme déjà pris. Déconnexion.");
                out.flush();
                socket.close();
                return;
            } else {
                out.writeBoolean(true);
                out.writeUTF("Bienvenue " + pseudonyme);
                out.flush();
            }
        }

        ClientHandler handler = new ClientHandler(socket, pseudonyme, aesKey, this, in, out);
        clients.put(pseudonyme, handler);
        broadcastSystemMessage(pseudonyme + " s'est connecté.");
        new Thread(handler).start();
        System.out.println("Client '" + pseudonyme + "' connecté.");
    }

    public void broadcast(String fromPseudonyme, String plainText) {

        String payload = fromPseudonyme + "::" + plainText;
       
        try {
            logWriter.write(new Date().toString() + " FROM " + fromPseudonyme + " : " + plainText);
            logWriter.newLine();
            logWriter.flush();
        } catch (IOException ignored) {}

        for (Map.Entry<String, ClientHandler> e : clients.entrySet()) {
            String dest = e.getKey();
            ClientHandler ch = e.getValue();
            if (!dest.equals(fromPseudonyme)) {
                ch.sendPlainAndEncrypt(payload);
            }
        }
    }

    public void broadcastSystemMessage(String msg) {
        String payload = "SERVER::" + msg;
        for (ClientHandler ch : clients.values()) {
            ch.sendPlainAndEncrypt(payload);
        }
        try {
            logWriter.write(new Date().toString() + " SYSTEM : " + msg);
            logWriter.newLine();
            logWriter.flush();
        } catch (IOException ignored) {}
    }

    public void removeClient(String pseudonyme) {
        clients.remove(pseudonyme);
        broadcastSystemMessage(pseudonyme + " s'est déconnecté.");
        System.out.println("Client '" + pseudonyme + "' supprimé.");
    }

    public static void main(String[] args) throws Exception {
        int port = 5555;
        if (args.length > 0) port = Integer.parseInt(args[0]);
        SecureChatServer server = new SecureChatServer(port);
        server.start();
    }
}
