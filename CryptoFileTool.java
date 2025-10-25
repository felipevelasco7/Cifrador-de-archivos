import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

public class CryptoFileTool {

    private static final int KEY_SIZE = 256;
    private static final int SALT_SIZE = 16;
    private static final int IV_SIZE = 16;
    private static final int ITERATIONS = 65536;

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Uso:");
            System.out.println("  Para cifrar: java CryptoFileTool encrypt <archivoEntrada> <archivoSalida>");
            System.out.println("  Para descifrar: java CryptoFileTool decrypt <archivoEntrada> <archivoSalida>");
            return;
        }

        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Ingrese la contraseña: ");
        String password = br.readLine();

        if (args[0].equalsIgnoreCase("encrypt")) {
            encryptFile(args[1], args[2], password);
        } else if (args[0].equalsIgnoreCase("decrypt")) {
            decryptFile(args[1], args[2], password);
        } else {
            System.out.println("Opción inválida. Use encrypt o decrypt.");
        }
    }

    public static void encryptFile(String inputFile, String outputFile, String password) throws Exception {
        // Generar salt y clave
        byte[] salt = generateRandomBytes(SALT_SIZE);
        SecretKey key = deriveKey(password, salt);

        // Generar IV
        byte[] iv = generateRandomBytes(IV_SIZE);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        // Leer archivo original
        byte[] inputData = readFile(inputFile);

        // Calcular hash SHA-256 del original
        byte[] hashOriginal = MessageDigest.getInstance("SHA-256").digest(inputData);

        // Cifrar datos
        byte[] encryptedData = cipher.doFinal(inputData);

        // Escribir archivo cifrado: [salt][iv][hash][datosCifrados]
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(hashOriginal);
            fos.write(encryptedData);
        }

        System.out.println("✅ Archivo cifrado correctamente: " + outputFile);
    }

    public static void decryptFile(String inputFile, String outputFile, String password) throws Exception {
        byte[] fileData = readFile(inputFile);

        // Extraer partes
        byte[] salt = Arrays.copyOfRange(fileData, 0, SALT_SIZE);
        byte[] iv = Arrays.copyOfRange(fileData, SALT_SIZE, SALT_SIZE + IV_SIZE);
        byte[] hashOriginal = Arrays.copyOfRange(fileData, SALT_SIZE + IV_SIZE, SALT_SIZE + IV_SIZE + 32);
        byte[] encryptedData = Arrays.copyOfRange(fileData, SALT_SIZE + IV_SIZE + 32, fileData.length);

        // Derivar clave
        SecretKey key = deriveKey(password, salt);

        // Descifrar
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decryptedData = cipher.doFinal(encryptedData);

        // Calcular hash y comparar
        byte[] hashNuevo = MessageDigest.getInstance("SHA-256").digest(decryptedData);

        if (Arrays.equals(hashOriginal, hashNuevo)) {
            writeFile(outputFile, decryptedData);
            System.out.println("Archivo descifrado correctamente y verificado: " + outputFile);
        } else {
            System.out.println("El hash no coincide. Integridad comprometida.");
        }
    }

    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static byte[] readFile(String filePath) throws IOException {
        return java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath));
    }

    private static void writeFile(String filePath, byte[] data) throws IOException {
        java.nio.file.Files.write(java.nio.file.Paths.get(filePath), data);
    }
}
