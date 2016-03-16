//
//  RSAKeyGenerator.java
//  455 Cryptogaphy Project
//
//  Created by Joseph Kalash on 1/12/14.
//  Copyright (c) 2014 Joseph Kalash. All rights reserved.
//

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
//import javax.crypto.KeyGenerator;
import java.security.SecureRandom;

public class RSAKeyGenerator
{
    /** Minimum key size allowed for RSA keys = 384 bits */
    private static final int MIN_KEY_SIZE = 384;
    
    /** Maximum key size allowed for RSA keys = 2048 bits */
    private static final int MAX_KEY_SIZE = 2048;
    
    public static void main(String args[]) throws Exception
    {
        System.out.println("RSAKeyGenerator");        
        System.out.println("-- generates a variable bit RSA key pair");        
        System.out.println("-- by Joseph Kalash");        
        System.out.println("------------------------------------------------------");
                
        if (args.length != 2) 
        {
            System.out.println("\nUsage:\nRSAKeyGenerator <KEY_BIT_SIZE> <KEY_FILE_PREFIX>");
            System.exit(1);
        }
        
        // Check whether the key size is valid
        int keySize = 0;
        try 
        {
            keySize = Integer.parseInt(args[0]);
            if(keySize < MIN_KEY_SIZE || keySize > MAX_KEY_SIZE)
                throw new NumberFormatException();
        }
        catch(NumberFormatException ex) 
        {
            System.out.println("\nUsage:\nRSAKeyGenerator <KEY_BIT_SIZE> <KEY_FILE_PREFIX>");
            System.out.println("+++ " + MIN_KEY_SIZE + " <= KEY_BIT_SIZE <= " + MAX_KEY_SIZE);
            System.exit(1);
        }
            
        // add our provider 
        System.out.println("+++ Adding Cryptix provider...");        
        java.security.Provider prov = new cryptix.jce.provider.CryptixCrypto();
        java.security.Security.addProvider( prov );
    
        // Initialize the key pair generator to execute an RSA key generation.
        System.out.println("+++ Initializing key generator...");        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA","CryptixCrypto");        
        keyGen.initialize(keySize, new SecureRandom());
        
        // generate a key
        System.out.println("+++ Generating " + keySize + " bit RSA key pair...");        
        KeyPair keyPair = keyGen.genKeyPair();
        
        // extract the key information from the key pair
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
            
        // write the private key out to a file
        String privateFileName = args[1] + ".private"; 
        System.out.println("+++ Outputting private key to file: " + privateFileName + "...");
        ObjectOutputStream privateStream = new ObjectOutputStream (new FileOutputStream(privateFileName, false));
        privateStream.writeObject(privateKey);
        privateStream.close();
        
        // write the public key out to a file
        String publicFileName = args[1] + ".public"; 
        System.out.println("+++ Outputting public key to file: " + publicFileName + "...");
        ObjectOutputStream publicStream = new ObjectOutputStream (new FileOutputStream(publicFileName, false));
        publicStream.writeObject(publicKey);
        publicStream.close();

        System.out.println("+++ Done...");        
    }
}
