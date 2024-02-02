package crypto;

import static crypto.Helper.cleanString;
import static crypto.Helper.stringToBytes;

import static crypto.Helper.bytesToString;

/*
 * Part 1: Encode (with note that one can reuse the functions to decode)
 * Part 2: bruteForceDecode (caesar, xor) and CBCDecode
 * Part 3: frequency analysis and key-length search
 * Bonus: CBC with encryption, shell
 */

public class Main {
	
	//---------------------------MAIN---------------------------
	
	public static void main(String args[]) {
		
		testCaesarExamples();
		testXORExamples();
		testOneTimePadExamples();
		testVigenereExamples();
						
//		solveChallenge();
						
//		runAllDemos(Helper.readStringFromFile("text_one.txt"));
//		runAllDemos(Helper.readStringFromFile("text_two.txt"));
//		runAllDemos(Helper.readStringFromFile("text_three.txt"));
		
//		Bonus62.run(args);
	}
	
	private static void runAllDemos(String inputMessage) {
		
		System.out.println("-------All demos-------");
		System.out.println("Original message : " + inputMessage);
		System.out.println();
		
		String messageClean = cleanString(inputMessage);
		byte[] messageBytes = stringToBytes(messageClean);
		byte[] pad = Encrypt.generatePad(3);
		
		runCaesar(messageBytes, pad[0]);	
		runXOR(messageBytes, pad[0]);
		runOneTimePad(messageBytes, Encrypt.generatePad(messageBytes.length));
		runCBC(messageBytes, pad);
		runVigenere(messageBytes, pad);
	}
	
	private static void runCaesar(byte[] originalMessage, byte key) {
		
		System.out.println("* Caesar :");
		System.out.println();
		
		//Encoding
		byte[] encoded_bytes = Encrypt.caesar(originalMessage, key);		
//		System.out.println("Encoded : " + bytesToString(encoded_bytes));
		
		//Decoding knowing key
		String decoded_str = bytesToString(Encrypt.caesar(encoded_bytes, (byte) (-key)));
		System.out.println("Decoded knowing the key : " + decoded_str);
		
		//Decoding with brute force
		byte[][] bruteForceResult = Decrypt.caesarBruteForce(encoded_bytes);
		String decodedBruteForce_str = Decrypt.arrayToString(bruteForceResult);
		Helper.writeStringToFile(decodedBruteForce_str, "bruteForceCaesar.txt");
		System.out.println("Open bruteForceCaesar.txt and check if the decoding succeeded");
		
		//Decoding with frequencies analysis
		String decodedWithFrq_str = Decrypt.breakCipher(Helper.bytesToString(encoded_bytes), Encrypt.CAESAR);
		System.out.println("Decoded with frequencies analysis : " + decodedWithFrq_str);
		
		System.out.println();
	}
	
	private static void runVigenere(byte[] originalMessage , byte[] keyword) {
		
		System.out.println("* Vigenere :");
		System.out.println();
		
		//Encoding
		byte[] encoded_bytes = Encrypt.vigenere(originalMessage, keyword);
//		System.out.println("Encoded : " + bytesToString(encoded_bytes));
		
		//Decoding with frequencies analysis
		String decodedWithFrq_str = Decrypt.breakCipher(Helper.bytesToString(encoded_bytes), Encrypt.VIGENERE);
		System.out.println("Decoded with frequencies analysis : " + decodedWithFrq_str);
		System.out.println();
	}
	
	private static void runXOR(byte[] originalMessage , byte key) {
		
		System.out.println("* XOR :");
		System.out.println();
		
		//Encoding
		byte[] encoded_bytes = Encrypt.xor(originalMessage, key);		
//		System.out.println("Encoded : " + bytesToString(encoded_bytes));
		
		//Decoding with brute force
		String decodedBruteForce_str = Decrypt.breakCipher(Helper.bytesToString(encoded_bytes), Encrypt.XOR);
		Helper.writeStringToFile(decodedBruteForce_str, "bruteForceXOR.txt");
		System.out.println("Open bruteForceXOR.txt and check if the decoding succeeded");

		System.out.println();
	}
	
	private static void runOneTimePad(byte[] originalMessage , byte[] pad) {
		
		System.out.println("* One time pad :");
		System.out.println();
		
		//Encoding
		byte[] encoded_bytes = Encrypt.oneTimePad(originalMessage, pad);		
//		System.out.println("Encoded : " + bytesToString(encoded_bytes));
		
		System.out.println();
	}
	
	private static void runCBC(byte[] originalMessage , byte[] pad) {
		
		System.out.println("* CBC :");
		System.out.println();
		
		//Encoding
		byte[] encoded_bytes = Encrypt.cbc(originalMessage, pad);		
//		System.out.println("Encoded : " + bytesToString(encoded_bytes));
		
		//Decoding knowing the key length
		byte[] cbcResult = Decrypt.decryptCBC(encoded_bytes, pad);
		String decoded_str = bytesToString(cbcResult);
		Helper.writeStringToFile(decoded_str, "decryptCBC.txt");
		System.out.println("Open decryptCBC.txt and check if the decoding succeeded");
		
		System.out.println();
	}
	
	public static void solveChallenge() {
		
		System.out.println("-------Challenge-------");
		
		// Decoding with vigenere frequencies
		byte[] encoded_bytes = stringToBytes(Helper.readStringFromFile("challenge-encrypted.txt"));
		String plainString = bytesToString(Decrypt.vigenereWithFrequencies(encoded_bytes));
		System.out.println("Challenge : " + plainString);
		
		System.out.println();
	}
	
	/**
	 * Compare two byte arrays.  We could also use Arrays.equal function but
     * using this avoids importing a Java library
	 * @param a1 first array to be compared
	 * @param a2 second array to be compared
	 * @return true if the arrays contain the same elements; false otherwise
	 */
	
	public static boolean MyCompareByteArrays(byte[] a1, byte[] a2) {
		
		if ((a1 == null) && (a2 == null))
			return true;

		if ((a1 == null) && (a2 != null))
			return false;

		if ((a1 != null) && (a2 == null))
			return false;
		
		// Les tableaux ne sont pas égaux si leur taille ne l'est pas
		if (a1.length != a2.length)
			return false;

		for (int i=0; i< a1.length; i++)
			if (a1[i] != a2[i]) 
				return false;
		
		return true;
		
	}

	public static void testCaesarExamples() {

		// Example 1: No shift.
		byte[] plainText = new byte[] {105, 32, 119, 97, 110, 116};
		byte[] expectedCipher = plainText;
		byte key = 0;
		byte[] cipherText = Encrypt.caesar(plainText , key);
		assert MyCompareByteArrays(cipherText, plainText): "Test Caesar 1 failed";		
		
		// Example 2: Example in the assignment
		plainText = 		new byte[] {105, 32, 119, 97, 110, 116};
		expectedCipher = 	new byte[] {-101, 32, -87, -109, -96, -90};		
		key = 50;
		cipherText = Encrypt.caesar(plainText , key);
		assert MyCompareByteArrays(cipherText, expectedCipher): "Test Caesar 2E failed";

		//Decoding with key
		byte[] expectedPlain = Encrypt.caesar(cipherText, (byte) (-key));
		assert MyCompareByteArrays(plainText, expectedPlain): "Test Caesar 2D failed";
		
		
		// Example 3: Example in the assignment
		plainText = new byte [] {105, 32, 119, 97, 110, 116};
		key = -120;
		
		cipherText = Encrypt.caesar(plainText , key);
		expectedCipher = new byte[] {-15, 32, -1, -23, -10, -4};
		assert MyCompareByteArrays(cipherText, expectedCipher): "Test Caesar 3E failed";

		//Decoding with key
		expectedPlain = Encrypt.caesar(cipherText, (byte) (-key));
		assert MyCompareByteArrays(plainText, expectedPlain): "Test Caesar 3D failed";


		// Example 4: Blank plaintext
		plainText = new byte [] {};
		key = 1;
		cipherText = Encrypt.caesar(plainText , key);
		expectedCipher = new byte[] {};
		assert MyCompareByteArrays(cipherText, expectedCipher): "Test Caesar 4 failed";
		
	}
	
	public static void testXORExamples() {

		// Example 1: Example in the assignment
		byte[] plainText = new byte[] {105, 32, 119, 97, 110, 116};
		byte[] expectedText = new byte [] {91, 32, 69, 83, 92, 70};
		byte key = 50;
		byte[] cipherText = Encrypt.xor(plainText , key);
		assert MyCompareByteArrays(cipherText, expectedText): "Test XOR 1 failed";
		
	}
	
	public static void testOneTimePadExamples() {

		byte[] plainText = Encrypt.generatePad(13);  // random plain text
		byte[] pad = Encrypt.generatePad(13);		 // random pad
		byte[] cipherText = Encrypt.oneTimePad(plainText, pad);
		assert MyCompareByteArrays(plainText, Encrypt.oneTimePad(cipherText, pad)): "Test OTP 1 failed";
		
	}
	
	public static void testVigenereExamples() {
		
		// Example 1: No shift.
		byte[] plainText = new byte[] {105, 32, 119, 97, 110, 116};
		byte[] keyword = new byte[] {0, 0};
		byte[] cipherText = Encrypt.vigenere(plainText , keyword);
		assert MyCompareByteArrays(cipherText, plainText): "Test vigenere 1 failed";
		
		// Example 2: Example in the assignment
		plainText = new byte[] {105, 32, 119, 97, 110, 116};
		keyword = new byte[] {50, -10, 100};
		cipherText = Encrypt.vigenere(plainText , keyword);
		byte[] expectedText = new byte[] {-101, 32, 109, -59, -96, 106};
		assert MyCompareByteArrays(cipherText, expectedText): "Test vigenere 2 failed";

		// For a key with one element only, we should get the same as Caesar
		plainText = new byte[] {105, 32, 119, 97, 110, 116};
		keyword = new byte[] {-120};
		cipherText = Encrypt.vigenere(plainText , keyword);
		expectedText = new byte[] {-15, 32, -1, -23, -10, -4};
		assert MyCompareByteArrays(cipherText, expectedText): "Test vigenere 3 failed";		
	
	}
}
