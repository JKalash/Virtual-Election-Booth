//
//  RSACertificateGenerator.java
//  455 Cryptogaphy Project
//
//  Created by Joseph Kalash on 1/12/14.
//  Copyright (c) 2014 Joseph Kalash. All rights reserved.
//

import java.io.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.Signature;

public class RSACertificateGenerator
{
    public static void main(String args[]) throws Exception
    {
        System.out.println("RSACertificateGenerator");        
        System.out.println("-- generates a signed hash of the input keys");        
        System.out.println("-- by Joseph Kalash");        
        System.out.println("------------------------------------------------------");
                
        if (args.length != 4) 
        {
            System.out.println("\nUsage:\nRSACertificateGenerator <CA_PRIVATE_KEY_FILE> <SIGNEE_PUB_KEY_FILE> <SIGNEE_NAME_TOKEN> <OUTPUT_FILE>");
            System.exit(1);
        }
                
        // add our provider 
        System.out.println("+++ Adding Cryptix provider...");        
        java.security.Provider prov = new cryptix.jce.provider.CryptixCrypto();
        java.security.Security.addProvider( prov );
    
        // Reading in CA private key
        System.out.println("+++ Reading CA private key from file: " + args[0] + "...");        
        ObjectInputStream privateStream = new ObjectInputStream (new FileInputStream(args[0]));
        RSAPrivateKey privateCAKey = (RSAPrivateKey)privateStream.readObject();
        privateStream.close();

        // Reading in SIGNEE public key
        System.out.println("+++ Reading SIGNEE public key from file: " + args[1] + "...");        
        ObjectInputStream publicStream = new ObjectInputStream (new FileInputStream(args[1]));
        RSAPublicKey publicSigneeKey = (RSAPublicKey)publicStream.readObject();
        publicStream.close();

        // Create the signature
        System.out.println("+++ Creating signature for: " + args[2] + "...");
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        ObjectOutputStream contentStream = new ObjectOutputStream(byteStream);
        contentStream.writeObject(publicSigneeKey);
        contentStream.writeObject(args[2]);
        
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(privateCAKey);
        sig.update(byteStream.toByteArray());
        byte[] cert = sig.sign();
        
        contentStream.close();
        byteStream.close();
        
        // write the cert out to a file
        String certFileName = args[3]; 
        System.out.println("+++ Outputting certificate to file: " + certFileName + "...");
        DataOutputStream certStream = new DataOutputStream (new FileOutputStream(certFileName, false));
        certStream.writeInt(cert.length);
        certStream.write(cert, 0, cert.length);
        certStream.close();
                 
        System.out.println("+++ Done...");        
    }
}
