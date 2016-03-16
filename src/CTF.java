//
//  CTF.java
//  455 Cryptogaphy Project
//
//  Created by Joseph Kalash on 1/12/14.
//  Copyright (c) 2014 Joseph Kalash. All rights reserved.
//

import java.net.*;
import java.io.*;
import java.util.*;

import javax.crypto.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.Signature;
import java.math.BigInteger;

//import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
 
public class CTF
{
    /** The port number on which to listen for communication */
    public static final int CTF_PORT = 7677;

    /** The public key for CTF */
    private RSAPublicKey m_publicKey = null;

    /** The private key for CTF */
    private RSAPrivateKey m_privateKey = null;

    /** The public key for the certificate authority (CA) for CTF.cert */
    private RSAPublicKey m_publicCAKey = null;
    
    /** The public certificate for CTF.public and "CTF" */
    private byte[] m_publicKeyCert;

    /** The voter list */
    private Hashtable<BigInteger, String> m_voterList = new Hashtable<BigInteger, String>();
    
    /** The candidate list */
    private Vector<String> m_candidateList = new Vector<String>();
    
    private boolean m_listening = false;

	private BufferedReader candStream;

    /**
     * Executes an instance of the CTF.
     */    
    public static void main(String args[]) throws Exception
    {
        System.out.println("CTF");        
        System.out.println("-- Virtual Election Booth");        
        System.out.println("-- by Joseph Kalash");        
        System.out.println();
        System.out.println("-- Enter q at the beginning of a line and hit enter to quit");
        System.out.println("------------------------------------------------------");
                    
        CTF CTF = new CTF();
        if(!CTF.start())
        {
            System.exit(1);
        }
    }
    
    /**
     * Starts the CTF by adding the Security provider, reading in all configuration
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
        
            // Reading in CTF public key
            System.out.println("+++ Reading CTF public key from file: CTF.public...");        
            ObjectInputStream stream = new ObjectInputStream (new FileInputStream("CTF.public"));
            m_publicKey = (RSAPublicKey)stream.readObject();
            stream.close();

            // Reading in CTF private key
            System.out.println("+++ Reading CTF private key from file: CTF.private...");        
            stream = new ObjectInputStream (new FileInputStream("CTF.private"));
            m_privateKey = (RSAPrivateKey)stream.readObject();
            stream.close();

            // Reading in cert
            System.out.println("+++ Reading certificate from file: CTF.cert...");        
            DataInputStream certStream = new DataInputStream (new FileInputStream("CTF.cert"));
            int certLength = certStream.readInt();
            m_publicKeyCert = new byte[certLength];
            certStream.read(m_publicKeyCert, 0, m_publicKeyCert.length);
            certStream.close();

            // Reading in CA public key
            System.out.println("+++ Reading CA public key from file: CA.public...");        
            stream = new ObjectInputStream (new FileInputStream("CA.public"));
            m_publicCAKey = (RSAPublicKey)stream.readObject();
            stream.close();

            // Reading in list of candidates
            System.out.println("+++ Reading list of voters from: CTF.candidates...");        
            candStream = new BufferedReader (new FileReader("CTF.candidates"));
            String candidate;
            while ((candidate = candStream.readLine()) != null) 
            {
                candidate = candidate.trim();
                if (candidate.length() > 0) 
                {
                    System.out.println("   +++ Adding candidate: " + candidate);        
                    m_candidateList.add(candidate);
                }
            }
            
            // start the server sockets
            System.out.println("+++ Starting CTF service on port " + CTF_PORT + "...");        
            ServerSocket serverSocket = new ServerSocket(CTF_PORT);
            m_listening = true;

            System.out.println("+++ Waiting for voter registrations...\n");        
            new ConsoleThread().start();
            while (m_listening)
                new CTFServerThread(serverSocket.accept()).start();
    
            serverSocket.close();
        }
        catch(Exception ex) 
        {
            System.out.println("*** Error starting CTF: " + ex + "\n");
            return false;
        }
        return true;
    }
    
    /**
     * This class handles the connections of VoterService or CLAService instances
     * that are requesting communication of data from the CTF.
     */
    class CTFServerThread extends Thread
    {
        /** The public key cipher we are using = RSA */
        private Cipher m_pkCipher = null;

        /** The symmetric cipher we are using = Blowfish */
        private Cipher m_cipher = null;

        private Socket m_socket = null;

        /**
         * Constructor for class CTFServerThread
         *
         * @param Socket socket: The socket on which to listen for communication
         */
        public CTFServerThread(Socket socket)
        {
            m_socket = socket;
        }
        
        /**
         * Causes the CTFServerThread to start listening for communication
         */ 
		public void run()
        {
            try 
            {
                System.out.println("### Received data from sender");
                m_pkCipher = Cipher.getInstance( "RSA/ECB/PKCS#1", "CryptixCrypto" );
                m_cipher = Cipher.getInstance( "Blowfish/ECB/PKCS#5", "CryptixCrypto" );

                ObjectOutputStream output = new ObjectOutputStream(m_socket.getOutputStream());
                ObjectInputStream input = new ObjectInputStream(m_socket.getInputStream());
                
                // first thing we do is send over our public key, and certificate. The user should
                // know that he is contacting the CTF, and be able to verify the certificate with
                // their CA public key.
                output.writeObject(m_publicKey);
                output.writeObject(m_publicKeyCert);
                
                // KEY-------------------
                // The user sends us a symmetric key first
                System.out.println("+++ Using private RSA key to decrypt symmetric Blowfish key from sender");
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

                // REQUEST -----------------
                // the user sends us his request as a string and their public key encrypted 
                // together using the symmetric key. 
                System.out.println("+++ Using symmetric Blowfish key to decrypt data from sender");
                byte[] encryptedRequest = (byte[])input.readObject();
                m_cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
                byte[] decryptedRequest = m_cipher.doFinal(encryptedRequest);
                
                // now extract the voter from the stream
                ObjectInputStream requestStream = new ObjectInputStream(new ByteArrayInputStream(decryptedRequest));
                RSAPublicKey userKey = (RSAPublicKey)requestStream.readObject();
                String request = (String)requestStream.readObject();
                
                // RESPONSE -----------------
                // Now we create our response based on the results of the search
                // through the system..
                ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
                ObjectOutputStream responseStream = new ObjectOutputStream(responseBytes);
                
                // CLA wishes to ADD a new validation number
                if (request.equals("ADD")) 
                {
                    // first thing we do, is validate that we are talking to the CLA, the
                    // CLA shall encrypt its certificate as the next object in the stream. To
                    // avoid someone from simply sending along the CLA's certificate along with
                    // its message, the entire message will be signed as well, and verified with
                    // the users public key.
                    byte [] cert = (byte [])requestStream.readObject();
                    BigInteger voterValidation = (BigInteger)requestStream.readObject();
                    byte [] userSig = (byte [])input.readObject();

                    System.out.println("+++ Contacted by CLA to add new ValidationId " + voterValidation);
                    System.out.println("+++ Verifying CA's signature of CLA's certificate");
                    System.out.println("+++ Verifying CLA's signature of data from CLA");

                    // here we verify the userKey and "CLA" pair
                    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
                    ObjectOutputStream contentStream = new ObjectOutputStream(byteStream);
                    contentStream.writeObject(userKey);
                    contentStream.writeObject(new String("CLA"));
                        
                    Signature sig = Signature.getInstance("SHA1withRSA");
                    sig.initVerify(m_publicCAKey);
                    sig.update(byteStream.toByteArray());
                    
                    // The CLA will sign the message before we add the validation number, we
                    // check this to make sure that it is actually the CLA making this request.
                    Signature sigCert = Signature.getInstance("SHA1withRSA");
                    sigCert.initVerify(userKey);
                    sigCert.update(decryptedRequest);
                                        
                    if (sig.verify(cert) && sigCert.verify(userSig)) 
                    {    
                        System.out.println("+++ CLA certificate and signature verified");                                                
                    
                        // now the CLA will send the voterValidationNumber, and we
                        // believe it to be the REAL CLA!!
                        m_voterList.put(voterValidation, new String(""));
                        responseStream.writeObject(new String("OK"));
                    }
                    else 
                    {
                        System.out.println("*** CLA certificate or signature invalid");
                        responseStream.writeObject(new String("ERROR"));
                        responseStream.writeObject(new String("Certificate or Signature Invalid"));                                
                    }
                    
                    contentStream.close();
                    byteStream.close();
                }
                // user wishes to get a list of the candidates
                else if (request.equals("LIST"))
                {
                    System.out.println("+++ Contacted by Voter to get candidate list");
                    responseStream.writeObject(new String("OK"));
                    responseStream.writeObject(m_candidateList);
                }
                // user wishes to vote
                else if (request.equals("VOTE"))
                {
                    BigInteger voterValidation = (BigInteger)requestStream.readObject();
                    String candidate = (String)requestStream.readObject();
                    System.out.println("+++ Contacted by Voter " + voterValidation + " to submit vote for " + candidate);

                    // make sure candidate exists
                    if (m_candidateList.contains(candidate)) 
                    {
                        // make sure validation number exists
                        if (m_voterList.get(voterValidation) != null) 
                        {
                            String currentVote = m_voterList.get(voterValidation);
                            
                            // can only vote once
                            if (currentVote.length() <= 0) 
                            {
                                System.out.println("+++ Accepted Voter's vote");
                                m_voterList.put(voterValidation, candidate);
                                responseStream.writeObject(new String("OK"));
                            }
                            else 
                            {
                                System.out.println("+++ Voter's vote already cast");
                                responseStream.writeObject(new String("ERROR"));
                                responseStream.writeObject(new String("Vote already cast"));                                                        
                            }
                        }
                        else 
                        {
                            System.out.println("+++ Invalid ValidationId");
                            responseStream.writeObject(new String("ERROR"));
                            responseStream.writeObject(new String("Validation Number Invalid"));                                
                        }
                    }
                    else 
                    {
                        System.out.println("+++ Invalid Candidate");
                        responseStream.writeObject(new String("ERROR"));
                        responseStream.writeObject(new String("Invalid Candidate"));                                
                    }
                }
                // user wishes to check their vote
                else if (request.equals("CHECK"))
                {
                    BigInteger voterValidation = (BigInteger)requestStream.readObject();
                    System.out.println("+++ Contacted by Voter " + voterValidation + " to verify vote");

                    String candidate = m_voterList.get(voterValidation);
                    if (candidate != null && candidate.length() > 0) 
                    {
                        System.out.println("+++ Vote for Voter " + voterValidation + " is registered for " + candidate);
                        responseStream.writeObject(new String("OK"));
                        responseStream.writeObject(candidate);
                    }
                    else 
                    {
                        System.out.println("+++ No vote has been recorded for Voter " + voterValidation);
                        responseStream.writeObject(new String("NONE"));
                    }
                }
                // user wishes to check results
                else if (request.equals("RESULTS"))
                {
                    System.out.println("+++ Contacted by Voter for election results");
                    int numCandidates = m_candidateList.size();
                    Vector<String> electionResults = new Vector<String>();
                    for(int i = 0; i < numCandidates; i++) 
                    {
                        String currentCandidateId = m_candidateList.elementAt(i);
                        int currentCandidateVoteCount = 0;
                        Collection<String> votes = m_voterList.values();
                        Iterator<String> voteIterator = votes.iterator();
                        while (voteIterator.hasNext())
                        {
                            if (currentCandidateId.equals(voteIterator.next()))
                            {
                                currentCandidateVoteCount++;
                            }
                        }
                        electionResults.add(new String(currentCandidateId + ": " + currentCandidateVoteCount));
                    }    
                    responseStream.writeObject(new String("OK"));
                    responseStream.writeObject(electionResults);
                }
                else 
                {
                    responseStream.writeObject(new String("ERROR"));
                    responseStream.writeObject(new String("unknown request"));
                }
                
                requestStream.close();
                
                // Put a time stamp in the message to guarantee its uniqueness with
                // respect to generating a signature of the data.
                responseStream.writeObject(new Long(System.currentTimeMillis()));
                
                // now we have the response, lets send it over encrypted with the
                // users symmetric key
                System.out.println("+++ Using symmetric Blowfish key to encrypt data for response to sender");
                m_cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
                byte[] encryptedResponse = m_cipher.doFinal(responseBytes.toByteArray());
                output.writeObject(encryptedResponse);
                
                // here we sign the decrypted bytes and send it to the user, so he
                // believes the results to be certified!                
                System.out.println("+++ Generating and sending an RSA signature of the data in the response");
                Signature sig = Signature.getInstance("SHA1withRSA");
                sig.initSign(m_privateKey);
                sig.update(responseBytes.toByteArray());
                output.writeObject(sig.sign());
                
                // and we are done
                System.out.println("### Done sending response to sender");
                responseStream.close();
                responseBytes.close();
                input.close();
                output.close();
                m_socket.close();
            }
            catch(Exception ex)
            {
                System.out.println("*** Error communicating with sender: " + ex);
                try
                {
                    m_socket.close();
                }
                catch(java.io.IOException ioe)
                {
                    ioe.printStackTrace();
                }    
            }
            System.out.println();
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
                System.out.println("CTF Closed by User...");
                System.exit(0);    
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
            }    
        }
    }
}
