package crypto;

import java.util.Scanner;

public class Bonus62 {

	private static Scanner scanner = new Scanner(System.in);
	
	/**
	 * This is the entry method for console application. We left the args parameter in case we decide to implement a command line
	 * such as Bonus62 -encrypt "clear plain text" or Bonus62 -encrypt -in "myPlainText.txt" -out "myCipherText.txt"
	 * @param args
	 */
	
	public static void run(String args[]) {
		
		while (true) {
			
			System.out.println("Welcome to CS-107 Mini-project 1: Cryptographie");
			System.out.println("...............................................");
			System.out.println();

			System.out.println("E : Encrypt text");
			System.out.println("D : Decrypt text");
			System.out.println("H : Help");
			System.out.println("Q : Quit");
			System.out.println();
			
			System.out.print("Selection : ");
			String response = scanner.nextLine();
			System.out.println();
			
			response = response.toLowerCase().strip();
			
			switch(response) {
							 	
				case "e":
					
					menuEncrypt();
				 	break;
				 				
				case "d":
					
					menuDecrypt();
				 	break;
				 	
				case "h":
					
					showHelp();
				 	break;
				 				
				case "q":
	        			
					System.out.println("Bye");
					System.out.println();
	        		scanner.close();
	        		return;
				 				
				default:
					
					break;
			}
		}
	}
	
	/**
	 * Method that explains to the user how the program works.
	 */
	
	private static void showHelp() {
		
		System.out.println("This program allows you to encrypt and decrypt text. The menu structure is as follows: ");
		System.out.println();
		
		System.out.println("   To type and encrypt text:");
		System.out.println("            Select E from the top menu");
		System.out.println("            Select T from the next menu");
		System.out.println("            Type the text to encrypt");
		System.out.println("            Select the encryption scheme");
		System.out.println("            Enter the encryption key");
		System.out.println("            The cipher text will be displayed on the screen");
		System.out.println();
		
		System.out.println("   To load and encrypt a file:");
		System.out.println("            Select E from the top menu");
		System.out.println("            Select L from the next menu");
		System.out.println("            Enter the input file name to encrypt");
		System.out.println("            Enter the output file name to save the the cipher text");
		System.out.println("            Select the encryption scheme");
		System.out.println("            Enter the encryption key");
		System.out.println("            The cipher text will be displayed on your output file");
		System.out.println();
		
		System.out.println("   To load and decrypt a file:");
		System.out.println("            Select D from the top menu");
		System.out.println("            Select L from the next menu");
		System.out.println("            Enter the input file name to decrypt");
		System.out.println("            Enter the output file name to save the decryption");
		System.out.println("            Choose if you want to decrypt with Vigenere, or Vigenere and XOR brute force");
		System.out.println("            The cipher text will be displayed on your output file");
		System.out.println();
		
		System.out.println("Press Enter to continue.");
		scanner.nextLine();
	}
	
	/**
	 * Method that ask the user if he wants to decrypt a file.
	 */
	
	private static void menuDecrypt() {
				
		while (true) {
		
			System.out.println("L : Load file to decrypt");
			System.out.println("P : Previous menu");
			System.out.println();
			
			System.out.print("Selection: ");
			String response = scanner.nextLine();
			System.out.println();
			
			response = response.toLowerCase().strip();
			
			switch(response) {
				 				
				case "l":
					
					decryptFile();
					return;
				 			
				case "p":
		
					return;
					
				default:
					
					break;
			}
		}
	}
	
	/**
	 * Method that asks the user the file name that he wants to decrypt, and the file name to copy the decryption.
	 * It also asks the user if he wants a Vigenere decryption only, or a Vigenere decryption and a XOR brute force.
	 */
	
	private static void decryptFile() {
		
		// file read :
		System.out.print("Please enter the file name to decrypt: ");
		String fileName = scanner.nextLine().trim();
		System.out.println();
		String fileText = getTextIfFileExists(fileName, "Could not read data from file.");
		if (fileText == "") { return; }
		
		// file write :
		System.out.print("Please enter the file name to save the decryption: ");
		fileName = scanner.nextLine().trim();
		System.out.println();
		checkFileNameNotEmpty(fileName, "File name not provided.");
		
		// Propose XOR brute force :
		while (true) {
		
			System.out.println("We will try to decrypt with Vigenere scheme. Do you also want to try with XOR brute force ?");
			System.out.println();
			
			System.out.println("Y : Yes");
			System.out.println("N : No");
			System.out.println();
			
			System.out.print("Response: ");
			String response = scanner.nextLine();
			System.out.println();
			
			response = response.toLowerCase().strip();
			
			switch(response) {
			
				case "y":
							
					decrypt(fileText, fileName, true);
	    			return;
				
				case "n":
					
					decrypt(fileText, fileName, false);
					return;
				 				
				default:
					
					break;
			}
		}		
	}
	
	/**
	 * Method that tries to decrypt the cipher text with Vigenere and/or with XOR brute force.
	 * @param cipherText is the cipher text to decrypt.
	 * @param fileName is the file name to copy the decryption.
	 * @param tryXOR is set to true if user wants to include the output of decryption using XOR brute force.
	 */
	
	private static void decrypt (String cipherText, String fileName, boolean tryXOR) {
			
		// Vigenere :
		String plainText = "* Decryption with Vigenere:";
		plainText += System.lineSeparator();
		plainText += System.lineSeparator();
		plainText += Decrypt.breakCipher(cipherText, Encrypt.VIGENERE);
		
		// XOR brute force :
		if (tryXOR) {
			
			plainText += System.lineSeparator();
			plainText += System.lineSeparator();
			plainText += "* Decryption with XOR brute force:";
			plainText += System.lineSeparator();
			plainText += System.lineSeparator();
			plainText += Decrypt.breakCipher(cipherText, Encrypt.XOR);
		}
		
		Helper.writeStringToFile(plainText, fileName);
		
		System.out.println("Your decrypted text has been saved in the file " + fileName + ". Press Enter to continue");
		System.out.println();
		
		scanner.nextLine();
	}
	
	/**
	 * Method that ask the user if he wants to encrypt a typed text or a file.
	 */
	
	private static void menuEncrypt() {	
				
		while (true) {
		
			System.out.println("T : Type text to encrypt");
			System.out.println("L : Load file to encrypt");
			System.out.println("P : Previous menu");
			System.out.println();
			
			System.out.print("Selection : ");
			
			String response = scanner.nextLine();
			System.out.println();
			
			response = response.toLowerCase().strip();
			
			switch(response) {
							 	
				case "t":
					
					encryptText();
				 	return;
				 				
				case "l":
		
					encryptFile();
					return;
								
				case "p": 	
        			
					return;
				 				
				default:
				
					break;
			}
		}
	}
	
	/**
	 * Method that asks the user the file name that he wants to encrypt, and the file name to copy the encryption.
	 */
	
	private static void encryptFile() {
		
		// file read :
		System.out.print("Please enter the file name to encrypt: ");
		String fileName = scanner.nextLine().trim();
		System.out.println();
		String fileText = getTextIfFileExists(fileName, "Could not read data from file.");
		if (fileText == "") { return; }
		
		// file write :
		System.out.print("Please enter the file name to save the encryption: ");
		fileName = scanner.nextLine().trim();
		System.out.println();
		checkFileNameNotEmpty(fileName, "File name not provided.");
		
		encrypt(fileText, fileName);
	}
	
	/**
	 * Method that checks if given file name is not empty.
	 * @param fileName is the file name
	 * @param messageError is the message to show if the file name is empty.
	 */
	
	private static void checkFileNameNotEmpty(String fileName, String messageError) {
		
		if (fileName == "") {
			
			System.out.println(messageError + " Press Enter to continue.");
			System.out.println();
			
			scanner.nextLine();
			return;
		}
	}
	
	/**
	 * Method that checks if a text file exists and read its text.
	 * @param fileName is the file name.
	 * @param messageError is the message to show if the file doesn't exist.
	 * @return the text read from the file.
	 */
	
	private static String getTextIfFileExists(String fileName, String messageError) {
		
		String text = Helper.readStringFromFile(fileName);
		
		if (text == "") {
			
			System.out.println(messageError + " Press Enter to continue.");
			System.out.println();
			
			scanner.nextLine();
		}
		
		return text;
	}
	
	/**
	 * Method tells the user to type a text to encrypt.
	 */
	
	private static void encryptText() {
		
		System.out.println("Please enter text to encrypt (start line with a dot '.' to finish): ");
		System.out.println();
		
		String plainText = "";
		String separator = "";
		String oneLine;
		
		do {
		
			oneLine = scanner.nextLine();
			
			if (!oneLine.startsWith(".")) {
				
				plainText += (separator + oneLine);
				separator = " ";
			}
			
		} while (!oneLine.startsWith("."));
		
		System.out.println();
		
		encrypt(plainText, "");
	}
	
	/**
	 * Method that encrypts a text with a given encryption scheme.
	 * @param plainText is the plain text to encrypt.
	 * @param fileName is the file name to copy the encryption.
	 */
	
	private static void encrypt (String plainText, String fileName) {
		
		plainText = Helper.cleanString(plainText);	
		
		int encryptionScheme = askEncryptionScheme();
		String key = askKey((encryptionScheme == Encrypt.ONETIME ? plainText.length() : 1));
		
		if (encryptionScheme == Encrypt.ONETIME && key.length() < plainText.length()) {
			
			System.out.println("Your key is too small. Cannot encrypt. Press Enter to continue.");
			scanner.nextLine();
			return;
		}
		
		String cipherText = Encrypt.encrypt(plainText, key, encryptionScheme);
		
		if (fileName == "") {
			
			showEncryptionSchemeAndKeyName(encryptionScheme, key);
			System.out.println(cipherText);
			System.out.println();
			
		} else {
			
			Helper.writeStringToFile(cipherText, fileName);
			System.out.print("Your encrypted text has been saved in the file " + fileName + ".");
			scanner.nextLine();
		}
		
		System.out.println("Press Enter to continue");
		scanner.nextLine();
	}
	
	/**
	 * Method that shows the name of encryption scheme and the key chosen by the user. The key will be cut if the encryption scheme is Caesar or XOR.
	 * @param method is the id of the encryption scheme chosen.
	 * @param key is the key chosen by the user.
	 */
	
	private static void showEncryptionSchemeAndKeyName(int encryptionScheme, String key) {
		
		String encryptionSchemeName = "";
		String keyName = key;
		
		switch (encryptionScheme) {
		
			case Encrypt.CAESAR : 
				
				encryptionSchemeName = "Caesar";
				keyName = String.valueOf(keyName.charAt(0));
				break;
			
			case Encrypt.VIGENERE : 
							
				encryptionSchemeName = "Vigenere";
				break;
							
			case Encrypt.XOR : 
				
				encryptionSchemeName = "XOR";
				keyName = String.valueOf(keyName.charAt(0));
				break;
				
			case Encrypt.ONETIME : 
				
				encryptionSchemeName = "One time pad";
				break;
				
			case Encrypt.CBC : 
				
				encryptionSchemeName = "CBC";
				break;
		}
		
		System.out.println("Here is your " + encryptionSchemeName + " encryption with the key [" + keyName + "]: ");
		System.out.println();
	}
	
	/**
	 * Method that tells the user to choose an encryption scheme between Caesar, Vigenere, XOR, One time pad and CBC.
	 * @return the id of encryption scheme chosen.
	 */
	
	private static int askEncryptionScheme() {
		
		System.out.println("Choose your encryption scheme : ");
		System.out.println();
		
		while (true) {
			
			System.out.println("C : Caesar");
			System.out.println("V : Vigenere");
			System.out.println("X : XOR");
			System.out.println("O : One time pad");
			System.out.println("B : CBC");
			System.out.println();
			
			System.out.print("Encryption scheme : ");
			String response = scanner.nextLine();
			System.out.println();
			
			response = response.toLowerCase().strip();
			
			switch(response) {
			
				case "c": return Encrypt.CAESAR;
							 	
				case "v": return Encrypt.VIGENERE;
				 				
				case "x": return Encrypt.XOR;
				 				
				case "o": return Encrypt.ONETIME;
				 				
				case "b": return Encrypt.CBC;
				 	
				default: break;					
			}
		}
	}
	
	/**
	 * Method that asks the user for a key.
	 * @param minLength is the minimum length of the key if the encryption scheme is One time pad.
	 * @return the key.
	 */
	
	private static String askKey(int minLength) {
		
		String key = "";
		
		do {
			
			if (minLength == 1) {
			
				System.out.print("Please enter your encryption key : ");
			
			} else {
				
				System.out.print("Please enter your encryption pad (min " + minLength + " characters): ");
			}
			
			key = scanner.nextLine();
			System.out.println();
			
		} while (key == "");
		
		return key;
	}
}
