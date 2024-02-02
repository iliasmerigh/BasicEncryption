package crypto;

import static crypto.Helper.bytesToString;
import static crypto.Helper.stringToBytes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Decrypt {
	
	
	public static final int ALPHABETSIZE = Byte.MAX_VALUE - Byte.MIN_VALUE + 1 ; //256
	public static final int APOSITION = 97 + ALPHABETSIZE/2; 
	
	//source : https://en.wikipedia.org/wiki/Letter_frequency
	public static final double[] ENGLISHFREQUENCIES = {0.08497,0.01492,0.02202,0.04253,0.11162,0.02228,0.02015,0.06094,0.07546,0.00153,0.01292,0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,0.07587,0.06327,0.09356,0.02758,0.00978,0.0256,0.0015,0.01994,0.00077};
	
	/**
	 * Method to break a string encoded with different types of cryptosystems
	 * @param type the integer representing the method to break : 0 = Caesar, 1 = Vigenere, 2 = XOR
	 * @return the decoded string or the original encoded message if type is not in the list above.
	 */
	
	public static String breakCipher(String cipher, int type) {
		
		byte[] cipherBytes = stringToBytes(cipher);
		
		switch (type) {
		
			case Encrypt.CAESAR :
			
				// On décrypte avec l'inverse de la clé de cryptage
				
				byte decodingKey = (byte) caesarWithFrequencies(cipherBytes);
				return bytesToString(Encrypt.caesar(cipherBytes, decodingKey));
			
			case Encrypt.VIGENERE :
				
				return bytesToString(vigenereWithFrequencies(cipherBytes));
			
			case Encrypt.XOR :
			
				byte[][] bruteForceResult = xorBruteForce(cipherBytes);
				return arrayToString(bruteForceResult);
			
			default : 
				
				return cipher;
		}		
	}
	
	/**
	 * Converts a 2D byte array to a String
	 * @param bruteForceResult a 2D byte array containing the result of a brute force method
	 */
	
	public static String arrayToString(byte[][] bruteForceResult) {
		
		assert (bruteForceResult != null);
		
		String result = "";
		
		for (int i = 0; i < bruteForceResult.length; i++) {
			
			result += bytesToString(bruteForceResult[i]);
			result += System.lineSeparator();
		}
		
		return result;
	}

	//-----------------------Caesar-------------------------
	
	/**
	 *  Method to decode a byte array  encoded using the Caesar scheme
	 * This is done by the brute force generation of all the possible options
	 * @param cipher the byte array representing the encoded text
	 * @return a 2D byte array containing all the possibilities
	 */
	
	public static byte[][] caesarBruteForce(byte[] cipher) {
		
		assert (cipher != null);
		
		byte[][] keysAndMessages = new byte[ALPHABETSIZE][cipher.length];
		
		for (int i = 0; i < ALPHABETSIZE; i++) {
			
			byte currentDecryptKey = (byte) (i - 128);
			keysAndMessages[i] = Encrypt.caesar(cipher, currentDecryptKey);
		}

		return keysAndMessages;
	}	
	
	/**
	 * Method that finds the inverse of the key to decode a Caesar encoding by comparing frequencies
	 * @param cipherText the byte array representing the encoded text
	 * @return the encoding key
	 */
	
	public static byte caesarWithFrequencies(byte[] cipherText) {
				
		float[] frequencies = computeFrequencies(cipherText);

		byte key = caesarFindKey(frequencies);
		
		return key;
	}
	
	/**
	 * Method that computes the frequencies of letters inside a byte array corresponding to a String
	 * @param cipherText the byte array 
	 * @return the character frequencies as an array of float
	 */
	
	public static float[] computeFrequencies(byte[] cipherText) {
		
		assert(cipherText != null);
		
		float[] frenquencies = new float[ALPHABETSIZE];
				
		// On ignore les espaces
		
		int cipherLengthWithoutSpaces = 0;
		
		for (int i = 0; i < cipherText.length; i++) {
			
			if (cipherText[i] != (byte) Encrypt.SPACE) {
				
				cipherLengthWithoutSpaces += 1;
				
				// Les bytes sont vont de -128 à 127, donc on les décale pour qu'ils entrent dans le tableau de 0 à 256
				
				int shiftedByte = cipherText[i] + 128;
				
				frenquencies[shiftedByte] += 1;
			}
		}
		
		if (cipherLengthWithoutSpaces != 0) {
			
			for (int i = 0; i < ALPHABETSIZE; i++) {
				
				frenquencies[i] = frenquencies[i] / cipherLengthWithoutSpaces;
			}
		}
		
		return frenquencies;
	}
	
	/**
	 * Method that finds the inverse of the key used by a Caesar encoding from an array of character frequencies
	 * @param charFrequencies the array of character frequencies
	 * @return the key
	 */
	
	public static byte caesarFindKey(float[] charFrequencies) {
		
		assert (charFrequencies != null);
		
		double scalaireMax = 0;
		int scalaireMaxIndex = 0;
		
		for (int i = 0; i < ALPHABETSIZE; i++) {
			
			double scalaire = 0;
			
			for (int j = 0; j < 26; j++) {
				
				scalaire += ENGLISHFREQUENCIES[j] * charFrequencies[(j + i) % ALPHABETSIZE];
			}
			
			if (scalaireMax < scalaire) {
				
				scalaireMax = scalaire;
				scalaireMaxIndex = i;
			}
		}
		
		// D'après la réctification apportée en cours, on retourne la clé de déchiffrement et non de chiffrement.
		// On décale les caractères de manière a obtenir l'index byte de 'a'
		
		byte key = (byte) (APOSITION - scalaireMaxIndex);
				
		return key;
	}
	
	//-----------------------XOR-------------------------
	
	/**
	 * Method to decode a byte array encoded using a XOR 
	 * This is done by the brute force generation of all the possible options
	 * @param cipher the byte array representing the encoded text
	 * @return the array of possibilities for the clear text
	 */
	
	public static byte[][] xorBruteForce(byte[] cipher) {
		
		assert (cipher != null);
		
		byte[][] keysAndMessages = new byte[ALPHABETSIZE][cipher.length];
		
		for (int i = 0; i < ALPHABETSIZE; i++) {
			
			byte currentDecryptKey = (byte) (i - 128);
			keysAndMessages[i] = Encrypt.xor(cipher, currentDecryptKey);
		}

		return keysAndMessages;
	}
	
	//-----------------------Vigenere-------------------------
	// Algorithm : see  https://www.youtube.com/watch?v=LaWp_Kq0cKs	
	
	/**
	 * Method to decode a byte array encoded following the Vigenere pattern, but in a clever way, 
	 * saving up on large amounts of computations
	 * @param cipher the byte array representing the encoded text
	 * @return the byte encoding of the clear text
	 */
	
	public static byte[] vigenereWithFrequencies(byte[] cipher) {
				
		List<Byte> cipherVigenereNoSpace = Decrypt.removeSpaces(cipher);
		int keyVigenereLength = Decrypt.vigenereFindKeyLength(cipherVigenereNoSpace);
		byte[] vigenereKeys = Decrypt.vigenereFindKey(cipherVigenereNoSpace, keyVigenereLength);
		
		byte[] plainText = Encrypt.vigenere(cipher, vigenereKeys);;
		
		return plainText;
	}
	
	/**
	 * Method that computes the key length for a Vigenere cipher text.
	 * @param cipher the byte array representing the encoded text without space
	 * @return the length of the key
	 */
	
	public static int vigenereFindKeyLength(List<Byte> cipher) {
		
		assert (cipher != null);
		
		byte[] cipherTable = new byte[cipher.size()];
			
		for (int i = 0; i < cipher.size(); i++) {
			
			cipherTable[i] = cipher.get(i);
		}
		
		int[] coincidences = getCoincidences(cipherTable);
		
		ArrayList<Integer> localMaxima = getLocalMaxIndices(coincidences);
		
		int keyLength = calculateKeyLength(localMaxima);
				
		return keyLength;
	}
	
	/**
	 * Method that counts the number of coincidences in the cipher text for each shift.
	 * @param cipher the byte array representing the encoded text without space.
	 * @return a table of the number of coincidences for each shift.
	 */
	
	private static int[] getCoincidences (byte[] cipher) {
		
		assert(cipher != null);
		
		// cipher.length - 1 : car on ne test pas la première coincidence entre j et j (on aurait une coincidence de 100%)
		
		int[] coincidences = new int[cipher.length - 1];
				
		for (int iter = 1; iter < cipher.length; iter++) {
						
			for (int j = 0; (j + iter) < cipher.length; j++) {
				
				if (cipher[j] == cipher[j + iter]) {
					
					coincidences[iter - 1] += 1;
				}
			}			
		}
		
		return coincidences;
	}
	
	/**
	 * Method that calculates the local maxima in the coincidences array.
	 * @param coincidences the int array representing the number of coincidences for each shift.
	 * @return an array list containing the local maxima of the coincidences array.
	 */
	
	private static ArrayList<Integer> getLocalMaxIndices (int[] coincidences) {
		
		assert (coincidences != null);
		
		ArrayList<Integer> localMaxIndices = new ArrayList<Integer>();
		
		int cipherHalfLength = (int) Math.ceil(coincidences.length / 2.0);
		
		int max = coincidences[0];
		
		for (int i = 0; i < coincidences.length; i++) {
			
			if (max < coincidences[i]) {
				
				max = coincidences[i];
			}
		}		
		
		for (int i = 0; i < cipherHalfLength; i++) {
			
			boolean left2_ok 	= 	((i - 2) < 0) 							|| 	coincidences[i - 2] < coincidences[i];
			boolean left1_ok 	= 	((i - 1) < 0) 							|| 	coincidences[i - 1] < coincidences[i];
			boolean right1_ok 	= 	((i + 1) >  coincidences.length - 1) 	|| 	coincidences[i + 1] < coincidences[i];
			boolean right2_ok 	= 	((i + 2) >  coincidences.length - 1) 	|| 	coincidences[i + 2] < coincidences[i];
			
			/* 	coincidences[i] > (max / 2) : car lorsqu'on veut la longeur de la clé, certains maximum locaux sont négligeables et donc il ne faut 
			 * 	s'interesser qu'aux plus grands.
			 */
			
			if ( left2_ok && left1_ok && right1_ok && right2_ok && coincidences[i] > (max / 2)) {

				localMaxIndices.add(i);
			}
		}
		
		return localMaxIndices;
	}
	
	/**
	 * Method that calculates the key length of a Vigenere encryption.
	 * @param localMaxIndices an array list containing the local maxima of the coincidences array.
	 * @return the key length.
	 */
	
	private static int calculateKeyLength (ArrayList<Integer> localMaxIndices) {
		
		assert (localMaxIndices != null);
		
		HashMap<Integer, Integer> localMaxIndicesDiff = new HashMap<Integer, Integer>();
		
		/* 	localMaxIndices.size() - 1 : car on compare la difference entre i et i+1 donc chaque i sera comparé 2 fois (à gauche puis à droite),
		 * 	sauf le premier et le dernier
		 */

		
		for (int i = 0; i < localMaxIndices.size() - 1; i++) {
			
			int difference = Math.abs(localMaxIndices.get(i) - localMaxIndices.get(i+1));
			
			int occurenceOfTheDifference = 1;
			
			if (localMaxIndicesDiff.containsKey(difference)) {
				
				occurenceOfTheDifference = localMaxIndicesDiff.get(difference) + 1;
			}
			
			localMaxIndicesDiff.put(difference, occurenceOfTheDifference);
		}
		
		int maxVal = 0; 
		int keyLength = 0;
		
		for (int difference : localMaxIndicesDiff.keySet()) {
			
			if (maxVal < localMaxIndicesDiff.get(difference)) {
				
				maxVal = localMaxIndicesDiff.get(difference);
				keyLength = difference;
			}
		}
		
		return keyLength;
	}
	
	/**
	 * Helper Method used to remove the space character in a byte array for the clever Vigenere decoding
	 * @param array the array to clean
	 * @return a List of bytes without spaces
	 */
	
	public static List<Byte> removeSpaces(byte[] array){
		
		assert (array != null);
		
		List<Byte> list = new ArrayList<Byte>();
		
		for (int i = 0; i < array.length; i++) {
			
			if (array[i] != (byte) Encrypt.SPACE) {
				
				list.add(array[i]);
			}
		}
		
		return list;
	}
	
	/**
	 * Takes the cipher without space, and the key length, and uses the dot product with the English language frequencies 
	 * to compute the shifting for each letter of the key
	 * @param cipher the byte array representing the encoded text without space
	 * @param keyLength the length of the key we want to find
	 * @return the inverse key to decode the Vigenere cipher text
	 */
	
	public static byte[] vigenereFindKey(List<Byte> cipher, int keyLength) {
		
		assert (cipher != null);
		
		byte[] keys = new byte[keyLength];
		
		/* On décrypte chaque caractère crypté avec le même caractère. Il y a donc autant de passages sur le text que de caractères dans la clé,
		 * mais on saute à chaque fois les caractères non cryptés avec le caractère en question.
		 */
		
		for (int i = 0; i < keyLength; i++) {
			
			ArrayList<Byte> cipherVigenerePart = new ArrayList<Byte>();
			
			for (int j = 0; (i + (j * keyLength)) < cipher.size(); j++) {
				
				cipherVigenerePart.add(cipher.get(i + (j * keyLength)));
			}
														
			byte[] cipherVigenerePartArray = new byte[cipherVigenerePart.size()];
			
			for (int k = 0; k < cipherVigenerePart.size(); k++) {
	
				cipherVigenerePartArray[k] = cipherVigenerePart.get(k);
			}
			
			keys[i] = Decrypt.caesarWithFrequencies(cipherVigenerePartArray);			
		}
		
		return keys;
	}
	
	
	//-----------------------Basic CBC-------------------------
	
	/**
	 * Method used to decode a String encoded following the CBC pattern
	 * @param cipher the byte array representing the encoded text
	 * @param iv the pad of size BLOCKSIZE we use to start the chain encoding
	 * @return the clear text
	 */
	
	public static byte[] decryptCBC(byte[] cipher, byte[] iv) {
		
		assert(cipher != null);
		assert(iv != null);
		
		byte[] plainText = new byte[cipher.length];
		
		// On copie "iv" dans une variable locale "pad" afin de garder le pad initial.
		
		byte[] pad = new byte[iv.length];
		
		for (int i = 0; i < iv.length; i++) {
			pad[i] = iv[i];
		}
		
		for (int i = 0; i < cipher.length; i++) {
			
			int currentPadIndex = (i % pad.length);
			
			plainText[i] = (byte) (cipher[i] ^ pad[currentPadIndex]);
			
			pad[currentPadIndex] = cipher[i];
		}
		
		return plainText;
	}
}
