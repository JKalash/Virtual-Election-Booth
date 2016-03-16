//
//  ServiceProvider.java
//  455 Cryptogaphy Project
//
//  Created by Joseph Kalash on 1/12/14.
//  Copyright (c) 2014 Joseph Kalash. All rights reserved.
//

public class ServiceProvider
{    
    /**
     * Exectutes an instance of the Service provided as the first argument.
     * The remaining arguments are passed directly to the service.
     */
    public static void main(String args[]) throws Exception
    {
        if (args.length == 0)
        {
            System.out.println("ServiceProvider");        
            System.out.println("-- Virtual Election Booth");        
            System.out.println("-- by Joseph Kalash");        
            System.out.println("------------------------------------------------------");
            System.out.println("Usage:\nServiceProvider <ServiceName> <Parameters for ServiceName>");        
            System.exit(1);
        }                            
        
        String newArgs[] = new String[args.length-1];
        for (int i=1; i<args.length; i++)
        {
            newArgs[i-1] = args[i];
        }
        if (args[0].equals("CTFService"))
        {
            CTFService.main(newArgs);
        }
        else if(args[0].equals("CLAService"))
        {
            CLAService.main(newArgs);
        }
        else if(args[0].equals("VoterService"))
        {
            VoterService.main(newArgs);
        }
        else if(args[0].equals("RSACertificateGenerator"))
        {
            RSACertificateGenerator.main(newArgs);
        }
        else if(args[0].equals("RSACertificateVerifier"))
        {
            RSACertificateVerifier.main(newArgs);
        }
        else if(args[0].equals("RSAKeyGenerator"))
        {
            RSAKeyGenerator.main(newArgs);
        }    
        else
        {
            System.out.println("Unrecognized service!");
        }        
    }
}