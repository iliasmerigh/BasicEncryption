# Bonus 6.1 - Extension du CBC:

- On a implémenté le CBC tel qu'il est décrit dans la page suivante https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC 
- On a choisi Vigenere comme méthode pour le "Block Cypher Encryption"
- Pour que cela fonctionne tout le temps, il faut appeler Vigenere en activant le codage d'espace car, par exemple si Vigenere décale 'a' (97) avec une clé de -65 alors sa version codé serait un espace
  qui sera confondu avec un espace dans le message original. Cela crée des problèmes quand cela passe ensuite par le XOR du CBC.
- L'idée essentielle est que durant le cryptage, on gère les tableaux bloc par bloc, où chaque bloc a la même taille que le iv.  On prend le premier bloc du "Plain Text", 
  et on lui fait un XOR avec le pad (le iv).  Ceci produit un bloc qui est aussi de la même taille que iv.  Ensuite on chiffre ce résultat avec la méthode Vigenere.  Ceci produit le premier 
  bloc du "Cypher Text".  Ce résultat est aussi copié dans le pad (le iv) à utiliser pour traiter le bloc suivant du "Plain Text".  Ceci se poursuit jusqu'à ce que l'on traite le 
  tableau "Plain Text" en entier.
- Le décryptage suit la même logique, mais dans le sens inverse.  On traite aussi le tableau "Cypher Text" bloc par bloc : on initialise un bloc, on le décrypte par Viegenere, et 
  on fait ensuite un XOR avec le iv (le pad).  En parallèle, on copie les éléments du bloc "Cypher Text" dans le iv (le pad) pour le traitement/décodage du bloc suivant.
  
On a fourni deux méthodes dans le fichier Bonus61.java:
  - La fonction "modifiedCBC"  exécute le programme décrit ci-dessus pour le codage d'un tableau de bytes en utilisant un iv et une clé de cryptage Vigenere.
  - La fonction "decryptModifiedCBC"  exécute la méthode decrite ci-dessus pour le décodage d'un tableau de bytes en utilisant un iv et une clé de cryptage Vigenere.
  - La fonction "test1ModifiedCBC" appelle les deux fonctions précédentes afin de coder et décoder un message (fourni en paramètre). Elle fait office d'exemple et est appelée dans la méthode main.
  - La fonction "test2ModifiedCBC" fait un test plus avancé en faisant des itérations sur la cclé et le iv.
  
  
# Bonus 6.2 - Interpréteur de Commande:


- L'interpréteur est fourni en tant que classe.  Pour exécuter le programme, il suffit de l'appeler comme suit:
		
	Bonus62.run(args)
		
- Le paramètre args n'est pas utilisé, et on peut passer null comme valeur.  Mais on a laissé ce paramètre car, si on avait plus de temps, on aurait
  implémenté une logique pour exécuter des commandes telles que:
     
     myProject -encrypt "This is a test" -m XOR -out "myOutputFile.txt"
     
- La version actuelle utilise un système de menus comme il est suggéré dans les instructions/énoncé du mini projet.
- Le programme ne gère pas toutes les possibilités.  Par exemple, si on veut que le résultat du codage soit sauvegardé dans un fichier, il faut fournir le texte à coder dans fichier.  
  Si on choisit de saisir manuellement le texte à coder, alors le résultat est affiché sur l'écran.