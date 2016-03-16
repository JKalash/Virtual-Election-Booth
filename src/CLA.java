//
//  CLA.java
//  455 Cryptogaphy Project
//
//  Created by Joseph Kalash on 1/12/14.
//  Copyright (c) 2014 Joseph Kalash. All rights reserved.
//

import java.net.*;
import java.io.*;
import javax.crypto.*;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.Signature;
import java.util.Hashtable;
import java.util.Random;
import java.math.BigInteger;


//import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;

public class CLA
{
    /** The port number on which to listen for communication */
    public static final int VOTER_TO_CLA_PORT = 7676;
    
    /** The port number on which to communicate with the CTF */
    public static final int CLA_TO_CTF_PORT = 7677;

    /** The name of the machine running the CTFService */
    private String m_CTFServerName = null;

    /** The public key for CLA */
    private RSAPublicKey m_publicKey = null;

    /** The private key for CLA */
    private RSAPrivateKey m_privateKey = null;

    /** The public key for the certificate authority (CA) for CLA.cert */
    private RSAPublicKey m_publicCAKey = null;
    
    /** The public certificate for CLA.public and "CLA" */
    private byte[] m_publicKeyCert;

    /** The voter list */
    private Hashtable<String, BigInteger> m_voterList = new Hashtable<String, BigInteger>();
    
    private boolean m_listening = false;

	private BufferedReader voterStream;

    /**
     * Constructor for class CLA.
     *
     * @param String CTFServerName: provides the address of the machine running the CTF.
     */
    CLA(String CTFServer)
    {
        m_CTFServerName = CTFServer;
    }

    /**
     * Executes an instance of the CLA.
     *
     * @param String CTFServerName: provides the address of the machine running the CTF.
     */
    public static void main(String args[]) throws Exception
    {
        System.out.println("CLA");        
        System.out.println("-- Virtual Election Booth");        
        System.out.println("-- by Joseph Kalash");        
        System.out.println();
        System.out.println("-- Enter q at the beginning of a line and hit enter to quit");
        System.out.println("------------------------------------------------------");
                    
        if (args.length != 1)                     
        {
            System.out.println("Usage:\nCLA <CTFServerName>");        
            System.exit(1);
        }                            
                    
        CLA CLA = new CLA(args[0]);
        if(!CLA.start())
        {
            System.exit(1);
        }
    }

    /**
     * Starts the CLA by adding the Security provider, reading in all configuration
     * files and creating the socket connections for receiving communication.
     *
     * @return true on success or false on failure
     */
    public boolean start() 
    {
        try 
        {
            // add our crypto provider 
            System.out.println("+++ Adding Cryptix provider...");        
            java.security.Provider prov = new cryptix.jce.provider.CryptixCrypto();
            java.security.Security.addProvider( prov );
        
            // Reading in CLA public key
            System.out.println("+++ Reading CLA public key from file: CLA.public...");        
            ObjectInputStream stream = new ObjectInputStream (new FileInputStream("CLA.public"));
            m_publicKey = (RSAPublicKey)stream.readObject();
            stream.close();

            // Reading in CLA private key
            System.out.println("+++ Reading CLA private key from file: CLA.private...");        
            stream = new ObjectInputStream (new FileInputStream("CLA.private"));
            m_privateKey = (RSAPrivateKey)stream.readObject();
            stream.close();

            // Reading in cert
            System.out.println("+++ Reading certificate from file: CLA.cert...");        
            DataInputStream certStream = new DataInputStream (new FileInputStream("CLA.cert"));
            int certLength = certStream.readInt();
            m_publicKeyCert = new byte[certLength];
            certStream.read(m_publicKeyCert, 0, m_publicKeyCert.length);
            certStream.close();

            // Reading in CA public key
            System.out.println("+++ Reading CA public key from file: CA.public...");        
            stream = new ObjectInputStream (new FileInputStream("CA.public"));
            m_publicCAKey = (RSAPublicKey)stream.readObject();
            stream.close();

            // Reading in list of voters
            System.out.println("+++ Reading list of voters from: CLA.voters...");        
            voterStream = new BufferedReader (new FileReader("CLA.voters"));
            String voter;
            while ((voter = voterStream.readLine()) != null) 
            {
                voter = voter.trim();
                if (voter.length() > 0) 
                {
                    System.out.println("   +++ Adding voter: " + voter);        
                    m_voterList.put(voter, BigInteger.ZERO);
                }
            }
            
            // start the server socket
            System.out.println("+++ Starting CLA service on port " + VOTER_TO_CLA_PORT + "...");        
            ServerSocket serverSocket = new ServerSocket(VOTER_TO_CLA_PORT);
            m_listening = true;

            System.out.println("+++ Waiting for voter registrations...");        
            new ConsoleThread().start();
            while (m_listening)
            {
                new CLAServerThread(serverSocket.accept()).start();
            }
            serverSocket.close();
        }
        catch(Exception ex) 
        {
            System.out.println("*** Error starting CLA: " + ex);
            return false;
        }
        return true;
    }

    /**
     * This class handles the connections of VoterService instances
     * that are requesting communication of data from the CLA.
     */
    class CLAServerThread extends Thread
    {
        /** The key size in bits for the symmetric cipher. Valid values are between 40 and 448 in 8 bit increments */
        private static final int KEY_SIZE = 448;

        /** The public key cipher we are using = RSA */
        private Cipher m_pkCipher = null;

        /** The symmetric cipher we are using = Blowfish */
        private Cipher m_cipher = null;

        private Socket m_socket = null;

		private RSAPublicKey voterKey;

        /**
         * Constructor for class CLAServerThread
         *
         * @param Socket socket: The socket on which to listen for communication
         */
        public CLAServerThread(Socket socket)
        {
            m_socket = socket;
        }
        
        /**
         * Causes the CLAServerThread to start listening for communication
         */
        public void run()
        {
            try 
            {
                System.out.println("\n### Received data from Voter");
                m_pkCipher = Cipher.getInstance( "RSA/ECB/PKCS#1", "CryptixCrypto" );
                m_cipher = Cipher.getInstance( "Blowfish/ECB/PKCS#5", "CryptixCrypto" );

                ObjectOutputStream output = new ObjectOutputStream(m_socket.getOutputStream());
                ObjectInputStream input = new ObjectInputStream(m_socket.getInputStream());
                
                // first thing we do is send over our public key, and certificate. The voter should
                // know that he is contacting the CLA, and be able to verify the certificate with
                // their CA public key.
                output.writeObject(m_publicKey);
                output.writeObject(m_publicKeyCert);
                
                // KEY-------------------
                // The user sends us a symmetric key first
                System.out.println("+++ Using private RSA key to decrypt symmetric Blowfish key from Voter");
                m_pkCipher.init(Cipher.DECRYPT_MODE, m_privateKey);
                byte[] decryptedKeyBytes = m_pkCipher.doFinal((byte[])input.readObject());

                ByteArrayInputStream keyBytes = new ByteArrayInputStream(decryptedKeyBytes);
                DataInputStream keyStream = new DataInputStream(keyBytes);
                
                // Recreate the users symmetric key
                String algorithm = keyStream.readUTF();
                int length = keyStream.readInt();
                byte[] encodedKey = new byte[length];
                keyStream.readFully(encodedKey);
                SecretKey symmetricKey = new SecretKeySpec(encodedKey, algorithm);
                
                // close the streams            
                keyStream.close();
                keyBytes.close();                
                
                // LOGIN -----------------
                // the user sends us his "voterid,password" as a string and public key encrypted 
                // together using our public key. 
                System.out.println("+++ Using symmetric Blowfish key to decrypt data from Voter");
                byte[] encryptedLogin = (byte[])input.readObject();
                m_cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
                byte[] decryptedLogin = m_cipher.doFinal(encryptedLogin);
                
                // now extract the voter from the stream
                ObjectInputStream loginStream = new ObjectInputStream(new ByteArrayInputStream(decryptedLogin));
                String voter = (String)loginStream.readObject();
                setVoterKey((RSAPublicKey)loginStream.readObject());
                
                // we are done with receiving information from the user
                loginStream.close();
            
                // RESPONSE -----------------
                // Now we create our response based on the results of the search
                // through the system
                ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
                ObjectOutputStream responseStream = new ObjectOutputStream(responseBytes);
                
                // if the validation of the voter list is null, the voter is not registered. If
                // the validation is zero, one has not been created yet.
                BigInteger voteValidation = (BigInteger)m_voterList.get(voter);
                if (voteValidation == null) 
                {
                    System.out.println("+++ Login of: " + voter + " rejected");
                    responseStream.writeObject(new String("ERROR"));
                    responseStream.writeObject(new String("Login rejected"));
                }
                else if (voteValidation.compareTo(BigInteger.ZERO) != 0) 
                {
                    System.out.println("+++ Login of " + voter + " accepted, returning previous ValidationId " + voteValidation);
                    responseStream.writeObject(new String("REPEAT"));
                    responseStream.writeObject(voteValidation);                    
                }
                else 
                {
                    // create a unique number, in reality we would test whether this number
                    // was already used.
                    voteValidation = new BigInteger(64, new Random());
                    System.out.println("+++ Login of " + voter + " accepted, creating new ValidationId " +voteValidation);
                    
                    // contact CTF and register the number                
                    if (doCTFRegister(voteValidation))                                 
                    {                                
                        // apply it to the hash table
                        m_voterList.put(voter, voteValidation);
                        responseStream.writeObject(new String("NEW"));
                        responseStream.writeObject(voteValidation);                    
                    }
                    else 
                    {
                        responseStream.writeObject(new String("ERROR"));
                        responseStream.writeObject(new String("CTF not responding!"));
                    }
                }
                
                // Put a time stamp in the message to guarantee its uniqueness with
                // respect to generating a signature of the data.
                responseStream.writeObject(new Long(System.currentTimeMillis()));
                
                // now we have the response, lets send it over encrypted with the
                // voters public key
                System.out.println("+++ Using symmetric Blowfish key to encrypt data for Voter");
                m_cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
                output.writeObject(m_cipher.doFinal(responseBytes.toByteArray()));
                
                // here we create the signature for the decrypted bytes and send
                // that over unencrypted.                
                System.out.println("+++ Generating and sending an RSA signature of the data to the Voter");
                Signature sig = Signature.getInstance("SHA1withRSA");
                sig.initSign(m_privateKey);
                sig.update(responseBytes.toByteArray());
                output.writeObject(sig.sign());
                
                // and we are done
                System.out.println("### Done sending response to Voter");
                responseStream.close();
                output.close();
                m_socket.close();
            }
            catch(Exception ex)
            {
                System.out.println("*** Error communicating with Voter: " + ex);
                try
                {
                    m_socket.close();
                }
                catch(java.io.IOException ioe)
                {
                    ioe.printStackTrace();
                }    
            }
        }
                
        /**
         * Contacts the CTF and requests that the vote validation number
         * be added to its list of authorized voters.
         *
         * @param BigInteger voteValidation: The voter validation number
         *
         * @return true on success or false on failure
         */
        private boolean doCTFRegister(BigInteger voteValidation)
        {
            boolean success = false;
            try 
            {
                System.out.println("\n### Sending data to CTF");
                Socket socket = new Socket(m_CTFServerName, CLA_TO_CTF_PORT);
                
                ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

                // Generating symmetric key
                System.out.println( "+++ Generating Blowfish key with bitsize " + KEY_SIZE + " for transmission to CTF" );
                KeyGenerator kg = KeyGenerator.getInstance("Blowfish","CryptixCrypto");
                kg.init(KEY_SIZE, new SecureRandom());
                SecretKey symmetricKey = kg.generateKey();
            
                RSAPublicKey ctfKey = (RSAPublicKey)input.readObject();
                byte[] ctfCert = (byte[])input.readObject();
                
                // here we verify the userKey and "CTF" pair
                ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
                ObjectOutputStream contentStream = new ObjectOutputStream(byteStream);
                contentStream.writeObject(ctfKey);
                contentStream.writeObject(new String("CTF"));
                    
                // verify the certificate sent by the CTF
                System.out.println("+++ Verifying CA's signature of CTF's certificate");
                Signature sig = Signature.getInstance("SHA1withRSA");
                sig.initVerify(m_publicCAKey);
                sig.update(byteStream.toByteArray());                
                if(!sig.verify(ctfCert))
                {
                    System.out.println("*** CTF certification failed");
                    socket.close();
                    return false;
                }
                else
                {
                    System.out.println("+++ CTF certificate verified");
                }    
                
                contentStream.close();
                byteStream.close();
                
                // KEY----------------------------------------
                // Send over the symmetric key encrypted with the cla public key
                ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
                DataOutputStream keyStream = new DataOutputStream(keyBytes);
                byte [] encodedKey = symmetricKey.getEncoded();
                keyStream.writeUTF(symmetricKey.getAlgorithm());
                keyStream.writeInt(encodedKey.length);
                keyStream.write(encodedKey, 0, encodedKey.length);
                
                // encrypt and send the symmetric key            
                System.out.println("+++ Using CTF's public RSA key to encrypt symmetric Blowfish key");
                m_pkCipher.init(Cipher.ENCRYPT_MODE, ctfKey);
                output.writeObject(m_pkCipher.doFinal(keyBytes.toByteArray()));

                // close the streams            
                keyStream.close();
                keyBytes.close();

                // REQUEST----------------------------------------
                // The following is formulated into a byte array and will be sent later
                ByteArrayOutputStream requestBytes = new ByteArrayOutputStream();
                ObjectOutputStream requestStream = new ObjectOutputStream(requestBytes);
                
                // send our public key and operation first
                System.out.println("+++ Contacting CTF to register new Voter " + voteValidation);
                requestStream.writeObject(m_publicKey);
                requestStream.writeObject(new String("ADD"));
                
                // next send the CLA certification, and signature of certification
                requestStream.writeObject(m_publicKeyCert);
                
                // now write out the voter validation number
                requestStream.writeObject(voteValidation);
                
                System.out.println("+++ Using symmetric Blowfish key to encrypt data for CTF");
                // encrypt and send the request
                m_cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
                byte[] encryptedRequest = m_cipher.doFinal(requestBytes.toByteArray());
                output.writeObject(encryptedRequest);

                // sign this message so that the CTF knows that it is us sending it
                System.out.println("+++ Generating and sending an RSA signature of data for CTF");
                sig.initSign(m_privateKey);
                sig.update(requestBytes.toByteArray());
                output.writeObject(sig.sign());
                        
                requestStream.close();
                
                // RESPONSE----------------------------------------        
                System.out.println("+++ Using symmetric Blowfish key to decrypt data from CTF");
                m_cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
                byte[] encryptedResponse = (byte[])input.readObject();
                byte[] decryptedResponse = m_cipher.doFinal(encryptedResponse);

                // Verify singature of the data
                System.out.println("+++ Verifying CTF signature of data from CTF");
                sig.initVerify(ctfKey);
                sig.update(decryptedResponse);                
                if(!sig.verify((byte[])input.readObject()))
                {
                    System.out.println("*** CTF signature failed\n");
                    socket.close();
                    return false;
                }
                else
                {
                    System.out.println("+++ CTF signature verified");
                }

                ObjectInputStream responseStream = new ObjectInputStream(new ByteArrayInputStream(decryptedResponse));
                String responseType = (String)responseStream.readObject();
                if (responseType.equals("OK")) 
                {
                    success = true;
                }
                else if(responseType.equals("ERROR")) 
                {
                    System.out.println("*** Error from CTF: " + (String)responseStream.readObject());
                }
                else 
                {
                    System.out.println("*** unknown response from CTF");
                }
                System.out.println("### Done receiving response from CTF");
                responseStream.close();
                socket.close();
            }
            catch(Exception ex)
            {
                if (ex.getClass().isInstance(new java.net.ConnectException())
                    || ex.getClass().isInstance(new java.io.EOFException()))
                {
                    System.out.println("*** Error communicating with CTF: " + ex.getMessage());
                }
                else
                {
                    ex.printStackTrace();
                }
                success = false;
            }
            System.out.println();
            return success;
        }

		public RSAPublicKey getVoterKey() {
			return voterKey;
		}

		public void setVoterKey(RSAPublicKey voterKey) {
			this.voterKey = voterKey;
		}
    }

    /**
     * This class handles the keypresses of the user at the console
     * allowing them to place a q at the beginning of a line and press
     * enter at any time to stop the service.
     */
    class ConsoleThread extends Thread
    {
        /** Starts the ConsoleThread listening for input from the user */
        public void run()
        {
            try
            {
                BufferedReader inputStream = new BufferedReader(new InputStreamReader(System.in));
                boolean exit = false;
                while (exit == false)
                {
                    String theKeys = inputStream.readLine();
                    if (theKeys.length() > 0)
                    {
                        if (theKeys.charAt(0) == 'q')
                        {
                            exit = true;
                        }
                    }    
                }
                System.out.println("CLA Closed by User...");
                System.exit(0);    
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
            }    
        }
    }
}
