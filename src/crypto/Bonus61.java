package crypto;

import static crypto.Helper.bytesToString;

public class Bonus61 {

	public static void main(String [] args) {
		
		String inputMessage = Helper.cleanString(Helper.readStringFromFile("text_one.txt"));
		test1ModifiedCBC(inputMessage);
		test2ModifiedCBC(inputMessage);
	}
	
	/**
	 * Method that runs the CBC-Vigenere encryption and show each step.
	 * @param plainText is the original text to encrypt, then to decrypt.
	 */
	
	private static void test1ModifiedCBC (String plainText) {
		
		System.out.println("Original input : " + plainText);
		System.out.println();
		
		// Pad pour le CBC
		byte[] pad = Encrypt.generatePad(8);
		
		// Clé arbitraire pour Vigenere
		byte[] key = {-10, 9, 32, -12, 7};
		
		byte[] plainBytes = Helper.stringToBytes(plainText);
		
		// Encrypt (pas besoin d'afficher le message crypté)
		String encryptedText = Helper.bytesToString(modifiedCBC(plainBytes, pad, key));
//		System.out.println("Encrypted : " + encryptedText);
		System.out.println();
		
		// Decrypt
		byte[] decryptedBytes = decryptModifiedCBC(Helper.stringToBytes(encryptedText), pad, key);
		String decryptedText = bytesToString(decryptedBytes);
		System.out.println("Decrypted : " + decryptedText);
		System.out.println();
	}
	
	private static void test2ModifiedCBC (String plainText) {

		plainText = Helper.cleanString(plainText);
		System.out.println("Original input : " + plainText);
		System.out.println();
		byte[] plainBytes = Helper.stringToBytes(plainText);
		
		for (int ipad = 3; ipad < 10; ipad++) {
			byte[] pad = Encrypt.generatePad(ipad);
			
			for (int ikey = 3; ikey < 10; ikey++) {
				byte[] key = Encrypt.generatePad(ikey);
								
				// Encrypt
				String encryptedText = Helper.bytesToString(modifiedCBC(plainBytes, pad, key));				
				// Decrypt
				byte[] decryptedBytes = decryptModifiedCBC(Helper.stringToBytes(encryptedText), pad, key);
				String decryptedText = bytesToString(decryptedBytes);

				if (!MyCompareByteArrays(decryptedBytes, plainBytes)) {
					System.out.println("ipad= " + ipad + ", ikey= " + ikey + ": "  + decryptedText);
				}
			}
		}
		
	}
	
	/**
	 * Method that encrypts a text with a combination of CBC and Vigenere.
	 * @param plainText is the text to encrypt.
	 * @param iv is the initial pad for CBC encryption.
	 * @param key is the key for Vigenere Encryption.
	 * @return the cipher text.
	 */
	
	public static byte[] modifiedCBC (byte[] plainText, byte[] iv, byte[] key) {
		
		assert(plainText != null);
		assert(iv != null);
		
		byte[] cipherText = new byte[plainText.length];
				
		// On copie "iv" dans une variable locale "pad" afin de garder le pad initial.
		
		byte[] pad = new byte[iv.length];
		
		for (int i = 0; i < iv.length; i++) {
			pad[i] = iv[i];
		}
				
		for (int i = 0, cipherIndex = 0; i < plainText.length; i++) {
			
			int currentPadIndex = (i % pad.length);
			
			pad[currentPadIndex] = (byte) (plainText[i] ^ pad[currentPadIndex]);
						
			if (currentPadIndex == pad.length - 1 || i == plainText.length - 1) {
				
				pad = Encrypt.vigenere(pad, key, true);
				
				for (int j = 0; j < pad.length && cipherIndex < cipherText.length; j++) {
					
					cipherText[cipherIndex] = pad[j];
					cipherIndex++;
				}
			}
		}
		
		return cipherText;
	}
	
	/**
	 * Method that decrypts a text encrypted with a combination of CBC and Vigenere.
	 * @param cipher is the cipher text to decrypt.
	 * @param iv is the initial pad for CBC encryption.
	 * @param key is the key for Vigenere Encryption.
	 * @return the plain text.
	 */
	
	public static byte[] decryptModifiedCBC (byte[] cipher, byte[] iv, byte[] key) {
		
		assert(cipher != null);
		assert(iv != null);
		
		byte[] plainText = new byte[cipher.length];		
		byte[] cipherBloc = new byte[iv.length];
		byte[] pad = new byte[iv.length];
		
		for (int i = 0; i < iv.length; i++) {
			pad[i] = iv[i];
		}
		
		/*
		 * On va parcourir le tableau cipher en utilisant l'index i.
		 * D'abord, on copie les éléments de cipher dans un tableau cipherBloc extrait de cipher de la même taille que iv.
		 * Une fois qu'on copie un bloc complet, on le décrypte avec Vigenere et on met le résultat dans decryptedCipherBloc.
		 * On peut alors faire le décryptage d'un extrait de cipher grâce à un XOR entre pad et decryptedCipherBloc.
		 * Le résultat de chaque XOR est sauvegardé dans le plainText et est aussi copié dans le pad pour utilisation dans l'extrait suivant.
		 * plainTextIndex correspond aux éléments du plainText; on ne l'incrémente donc que quand on réalise les XOR.
		 */
		
		for (int i = 0, plainTextIndex = 0; i < cipher.length; i++) {
			
			int currentPadIndex = (i % pad.length);
			
			cipherBloc[currentPadIndex] = cipher[i];
			
			if (currentPadIndex == pad.length - 1 || i == plainText.length - 1) {
				
				byte[] decryptedCipherBloc = vigenereDecryptWithKey(cipherBloc, key);
				
				for (int j = 0; j < pad.length && plainTextIndex < cipher.length; j++) {
					
					plainText[plainTextIndex] = (byte) (decryptedCipherBloc[j] ^ pad[j]);
					
					pad[j] = cipher[plainTextIndex];
					
					plainTextIndex++;
				}
			}
		}
		
		return plainText;
	}
	
	/**
	 * Method that decrypts a cipher text encrypted with Vigenere. This method need the encryption key.
	 * @param cipher is the cipher text to decrypt.
	 * @param encryptionKey is the encryption key used to encrypt with Vigenere.
	 * @return the plain text.
	 */
	
	private static byte[] vigenereDecryptWithKey (byte[] cipher, byte[] encryptionKey) {
				
		byte[] decryptionKey = new byte[encryptionKey.length];
		
		// On inverse la clé de cryptage pour avoir celle de décryptage
		
		for (int i = 0; i < encryptionKey.length; i++) {
			
			decryptionKey[i] = (byte) (-encryptionKey[i]);
		}
		
		byte[] plainText = Encrypt.vigenere(cipher, decryptionKey, true);
		
		return plainText;
	}
	
	/**
	 * Method that compares if two arrays contain the same elements
	 * @param a1 is the first array
	 * @param a2 is the second array
	 * @return true if they contain the same elements
	 */
	
	private static boolean MyCompareByteArrays(byte[] a1, byte[] a2) {
		
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
}
