#CD into local directory
BASEDIR=$(dirname $0);
cd ${BASEDIR};

#Launch jar
java -jar VirtualElectionBooth.jar VoterService localhost localhost;