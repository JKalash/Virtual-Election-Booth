//
//  RSACertificateVerifier.java
//  455 Cryptogaphy Project
//
//  Created by Joseph Kalash on 1/12/14.
//  Copyright (c) 2014 Joseph Kalash. All rights reserved.
//

import java.io.*;
//import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.Signature;

public class RSACertificateVerifier
{
    public static void main(String args[]) throws Exception
    {
        System.out.println("RSACertificateVerifier");        
        System.out.println("-- tests a signed hash of the input keys");        
        System.out.println("-- by Joseph Kalash");        
        System.out.println("------------------------------------------------------");
                
        if (args.length != 4) 
        {
            System.out.println("\nUsage:\nRSACertificateVerifier <CA_PUBLIC_KEY_FILE> <SIGNEE_PUB_KEY_FILE> <SIGNEE_NAME_TOKEN> <CERT_FILE>");
            System.exit(1);
        }
                
        // add our provider 
        System.out.println("+++ Adding Cryptix provider...");        
        java.security.Provider prov = new cryptix.jce.provider.CryptixCrypto();
        java.security.Security.addProvider( prov );
    
        // Reading in CA public key
        System.out.println("+++ Reading CA public key from file: " + args[0] + "...");        
        ObjectInputStream publicCAStream = new ObjectInputStream (new FileInputStream(args[0]));
        RSAPublicKey publicCAKey = (RSAPublicKey)publicCAStream.readObject();
        publicCAStream.close();

        // Reading in SIGNEE public key
        System.out.println("+++ Reading SIGNEE public key from file: " + args[1] + "...");        
        ObjectInputStream publicSigneeStream = new ObjectInputStream (new FileInputStream(args[1]));
        RSAPublicKey publicSigneeKey = (RSAPublicKey)publicSigneeStream.readObject();
        publicSigneeStream.close();

        // read the cert from a file
        String certFileName = args[3]; 
        System.out.println("+++ Reading certificate from file: " + certFileName + "...");
        DataInputStream certStream = new DataInputStream (new FileInputStream(certFileName));
        int certLength = certStream.readInt();
        byte [] cert = new byte[certLength];
        certStream.read(cert, 0, cert.length);
        certStream.close();

        // Create the signature
        System.out.println("+++ Verifying signature for: " + args[2] + "...");        
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        ObjectOutputStream contentStream = new ObjectOutputStream(byteStream);
        contentStream.writeObject(publicSigneeKey);
        contentStream.writeObject(args[2]);
            
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(publicCAKey);
        sig.update(byteStream.toByteArray());
                
        if (sig.verify(cert)) 
        {    
            System.out.println("+++ Certificate verified!!");                                
        }
        else 
        {
            System.out.println("*** CERTIFICATE INVALID ***");                                
        }
        
        contentStream.close();
        byteStream.close();
    }
}
