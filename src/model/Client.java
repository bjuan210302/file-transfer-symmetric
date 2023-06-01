package model;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;

public class Client {
	private Socket echoSocket;
	private String clientHost;
	private int port;
	private DataOutputStream toServer;
	private DataInputStream fromServer;
	private Key key;
	public static String CLIENT_FOLDER = "ClientFiles/";

	public Client() {
		clientHost = "127.0.0.1";
		port = 9090;
	}

	public static void main(String[] args) throws Exception {

		Client client = new Client();
		client.connect();

		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

		try {
			client.initializeDiffieHelman();
			System.out.println("Name of the file to send. Should be inside " + CLIENT_FOLDER);
			String filename = br.readLine();

			client.generateSHA256(CLIENT_FOLDER, filename);

		} catch (Exception e) {
			e.getStackTrace();
		}

	}

	public void connect() {
		try {
			echoSocket = new Socket(clientHost, port);
			toServer = new DataOutputStream(echoSocket.getOutputStream());
			fromServer = new DataInputStream(new DataInputStream(echoSocket.getInputStream()));
			System.out.println("Connected to server: " + echoSocket.getRemoteSocketAddress());
			// echoSocket.close();
		} catch (UnknownHostException e) {
			System.err.println("Non-existent host or wrong input " + clientHost);
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Couldn't get I/O for the connection to " + clientHost);
			System.exit(1);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void generateSHA256(String parentDirectoryPath, String fileName) throws Exception {

		tellServer("takeFile");
		String normalFilePath = parentDirectoryPath + fileName;
		tellServer(fileName);

		System.out.println("Encrypting:" + normalFilePath);
		String encryptedData = encryptFile(normalFilePath, key);
		File encryptedFile = new File(parentDirectoryPath + "clientFileEncrypted.txt");
		FileOutputStream outputStream = new FileOutputStream(encryptedFile);
		outputStream.write(encryptedData.getBytes());
		outputStream.close();

		MessageDigest md = MessageDigest.getInstance("SHA-256");

		InputStream is = new FileInputStream(normalFilePath);
		String hash = toHexString(md.digest(is.readAllBytes()));
		is.close();

		tellServer(hash);

		// Se envia el archivo cifrado al servidor
		sendFile(encryptedFile);
		System.out.println("Normal file path: " + normalFilePath);
		System.out.println("Normal file sha-256: " + hash);

		// Tells server to stop listening
		System.out.println("Exit");
		tellServer("exit");
		echoSocket.close();
	}

	private String encryptFile(String fullPath, Key secretKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, IOException {
		Cipher cipher = Cipher.getInstance("AES");
		byte[] textByte = Files.readAllBytes(Paths.get(fullPath));
		String encryptedFile = "";

		try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] encrypted = cipher.doFinal(textByte);
			Base64.Encoder encoder = Base64.getEncoder();
			encryptedFile = encoder.encodeToString(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return encryptedFile;
	}

	public static String toHexString(byte[] hash) {
		// Convert byte array into signum representation
		BigInteger number = new BigInteger(1, hash);

		// Convert message digest into hex value
		StringBuilder hexString = new StringBuilder(number.toString(16));

		// Pad with leading zeros
		while (hexString.length() < 64) {
			hexString.insert(0, '0');
		}

		return hexString.toString();
	}

	public void initializeDiffieHelman() throws NoSuchAlgorithmException, InvalidParameterSpecException, IOException {

		tellServer("diffie");
		AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
		paramGen.init(1024, new SecureRandom());
		AlgorithmParameters params = paramGen.generateParameters();
		DHParameterSpec dhSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);

		Random randomGenerator = new Random();

		BigInteger a = new BigInteger(1024, randomGenerator); // El secreto(privado)
		BigInteger p = dhSpec.getP(); // Numero primo(publico)
		BigInteger g = dhSpec.getG(); // Numero Primo generador de primos (publico)

		BigInteger A = g.modPow(a, p); // llave del cliente (A=g^a(modp)) (publico)

		// Mandar el numero primo
		tellServer(p.toString());

		// mandar Primo generador de primos
		tellServer(g.toString());

		// mandar calculo de A (llave cliente)
		tellServer(A.toString());
		// Recibir la llave
		BigInteger B = new BigInteger(fromServer.readUTF());

		// Calcular la llave secreta
		BigInteger encryptionKey = B.modPow(a, p);

		GenKeys gk = new GenKeys();
		key = gk.generateKey(encryptionKey.toByteArray());

	}

	public void sendFile(File file) {
		try {
			FileInputStream fileIn = new FileInputStream(file);
			byte[] buffer = new byte[Short.MAX_VALUE];
			int bytes = fileIn.read(buffer, 0, buffer.length);
			toServer.write(buffer, 0, bytes);
			fileIn.close();
		} catch (IOException i) {

		}

	}

	public void tellServer(String message) throws IOException {
		toServer.writeUTF(message);
		toServer.flush();
	}

}
