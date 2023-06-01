package model;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Server {
	private int port;
	private DataOutputStream out;
	private DataInputStream clientInput;
	private ServerSocket serverSocket;
	private Socket clientSocket;
	private String serverSHA;
	private String normalSHA;
	private String targetFileName;
	private String encryptedFilePath;
	public static String SERVER_FOLDER = "ServerFiles/";

	private Key serverKey;

	public Server() {
		port = 9090;
		serverSHA = "";
		targetFileName = "";
		encryptedFilePath = "ServerFiles/encryptedReceivedFile.txt";
	}

	public static void main(String[] args) {
		Server server = new Server();
		server.start();

		while (true) {
			try {
				if (server.listen() == 1)
					break;
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public void start() {
		try {
			serverSocket = new ServerSocket(port);
			clientSocket = serverSocket.accept();

			out = new DataOutputStream(clientSocket.getOutputStream());
			clientInput = new DataInputStream(new DataInputStream(clientSocket.getInputStream()));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public Key generateKey(byte[] key) {
		byte[] byteKey = new byte[16];
		for (int i = 0; i < 16; i++) {
			byteKey[i] = key[i];
		}
		try {
			Key keyAES = new SecretKeySpec(byteKey, "AES");
			return keyAES;
		} catch (Exception e) {
			System.out.println("Error while generating key" + e);
		}
		return null;
	}

	public String decryptFile(String filePath, Key secretKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, IOException {
		File toDecrypt = new File(filePath);
		String enc = "";
		String line = "";
		BufferedReader obj = new BufferedReader(new FileReader(toDecrypt));
		while ((line = obj.readLine()) != null) {
			enc += line;
		}
		obj.close();
		Cipher cipher = Cipher.getInstance("AES");
		Base64.Decoder decoder = Base64.getDecoder();
		byte[] encrypted = decoder.decode(enc);

		String decryptedFile = "";
		try {

			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] decrypted = cipher.doFinal(encrypted);
			decryptedFile = new String(decrypted);

			writeFile(new File(SERVER_FOLDER + targetFileName), decryptedFile.getBytes());

			MessageDigest md = MessageDigest.getInstance("SHA-256");

			String digest = toHexString(md.digest(decryptedFile.getBytes(StandardCharsets.UTF_8)));
			serverSHA = digest;

		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("Calculated Server: " + serverSHA);
		System.out.println("Are the SHA's equals: " + normalSHA.equals(serverSHA));
		return decryptedFile;
	}

	public static String toHexString(byte[] hash) {
		BigInteger number = new BigInteger(1, hash);
		StringBuilder hexString = new StringBuilder(number.toString(16));
		while (hexString.length() < 64) {
			hexString.insert(0, '0');
		}

		return hexString.toString();
	}

	public int listen() throws IOException {
		int interrupt = -1;
		String command;
		try {
			command = clientInput.readUTF();
			System.out.println("model.Client command: " + command);
			switch (Objects.requireNonNull(command)) {
				case "diffie" -> DiffieHelmanAnswer();
				case "takeFile" -> {
					targetFileName = clientInput.readUTF();
					normalSHA = clientInput.readUTF();
					System.out.println("Filename: " + targetFileName);
					System.out.println("SHA-265 received from client: " + normalSHA);
					receiveFile(new File(encryptedFilePath));
					decryptFile(encryptedFilePath, serverKey);
				}
				case "exit" -> {
					clientSocket.close();
					serverSocket.close();
					interrupt = 1;
					System.out.println("Connection terminated by client");
				}
				default -> {
					out.writeUTF("Command not found");
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return interrupt;
	}

	public void DiffieHelmanAnswer() throws IOException {
		// Recibe params del DiffieHelman
		BigInteger p = new BigInteger(clientInput.readUTF());
		BigInteger g = new BigInteger(clientInput.readUTF());
		BigInteger A = new BigInteger(clientInput.readUTF());

		// Generar el b secreto
		Random randomGenerator = new Random();
		BigInteger b = new BigInteger(1024, randomGenerator);
		// Calcular el B publico
		BigInteger B = g.modPow(b, p);

		// Mandar el B publico
		out.writeUTF(B.toString());

		// Calcular la llave secreta
		BigInteger decryptionKey = A.modPow(b, p);
		// Generar llave AES
		serverKey = generateKey(decryptionKey.toByteArray());

	}

	public void receiveFile(File file) throws IOException {
		FileOutputStream fileOut = new FileOutputStream(file);
		byte[] buf = new byte[Short.MAX_VALUE];
		int bytes = clientInput.read(buf, 0, buf.length);
		fileOut.write(buf, 0, bytes);
		fileOut.close();
	}

	private void writeFile(File file, byte[] data) {
		try (FileOutputStream outputStream = new FileOutputStream(file)) {
			outputStream.write(data);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
