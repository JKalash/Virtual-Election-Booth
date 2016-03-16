**    Virtual Election Booth     **
** Joseph Kalash & Karim Kaafarani **

** Instructions on how to run the System **

   There are a series of batch files in this (\virtualElectionBooth\) directory that automate
   the execution of several components of the system:

   Run.command      	(Runs all three services in new console windows.
                         No parameters are needed, the services are configured to run on localhost.)
   runCTF.command       (Runs the CLAService.)
   runCLA.command       (Runs the CLAService - Run with no params to see usage info.)
   runVoter.command     (Runs the VoterService - Run with no params to see usage info.)

** Instructions on how to build the System: **

   The system is built by compiling all source files in the source (\virtualElectionBooth\src) directory
   and building a jar file out of these classes, and the classes that make up the Cryptix Security
   Provider libraries, and placing in this directory.

   This process was already automated.
   The resulting jar file has the advantage of being compressed and requiring no environment variables
   to be run.

**    Virtual Election Booth     **

The following is a brief overview of the contents of this directory:

CA.private                     - CA's (Certificate Authority) Private RSA Key File.
CA.public                      - CA's (Certificate Authority) Public RSA Key File.
CLA.cert                       - CLA's (Central Legitimization Agency) Certificate.
CLA.private                    - CLA's (Central Legitimization Agency) Private RSA Key File.
CLA.public                     - CLA's (Central Legitimization Agency) Public RSA Key File.
CLA.voters                     - CLA's (Central Legitimization Agency) VoterId to ValidationId records.
CTF.cert                       - CTF's (Central Tabulating Facility) Certificate.
CTF.private                    - CTF's (Central Tabulating Facility) Private RSA Key File.
CTF.public                     - CTF's (Central Tabulating Facility) Public RSA Key File.
CTF.candidate                  - CTF's (Central Tabulating Facility) List of candidates for election.
Voter.private                  - Voter's Private RSA Key File.
Voter.public                   - Voter's Public RSA Key File.
VirtualElectionBooth.jar       - Executable Jar File containing all Source Code and Libraries needed for execution.