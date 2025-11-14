package chiffrement;

public class message {
public final String pseudo;
public final String text;
public message(String pseudo, String text) {
   this.pseudo = pseudo;
   this.text = text;
}
public String serializePlain() {
   return pseudo + "|" + text;
}
public static message deserializePlain(String plain) {
   int idx = plain.indexOf('|');
   if (idx < 0) return new message("?", plain);
   String p = plain.substring(0, idx);
   String t = plain.substring(idx + 1);
   return new message(p, t);
}
}