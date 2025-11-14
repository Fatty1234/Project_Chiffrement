package chiffrementclient;

public class Message {
 public final String pseudo;
 public final String text;
 public Message(String pseudo, String text) {
     this.pseudo = pseudo;
     this.text = text;
 }
 public String serializePlain() {
     return pseudo + "|" + text;
 }
 public static Message deserializePlain(String plain) {
     int idx = plain.indexOf('|');
     if (idx < 0) return new Message("?", plain);
     String p = plain.substring(0, idx);
     String t = plain.substring(idx + 1);
     return new Message(p, t);
 }
}