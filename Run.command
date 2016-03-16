#CD into local directory
BASEDIR=$(dirname $0);
cd ${BASEDIR};


#Launch the CTFService in a new Terminal Window
echo Starting CTF Service…;
sh runCTF.command;


#Launch the CLAService in a new Terminal Window
echo Starting CLA Service…;
sh runCLA.command;


#Launch the Voter in a new Terminal Window
echo Starting Voter Service…;
sh runVoter.command;
