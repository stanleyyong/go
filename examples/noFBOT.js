var StellarSdk = require('stellar-sdk');

//These two lines set up our SDK to point to the Standalone node for World Wire
//Note that I've hard coded the current location of that server, so please
//modify the actual IP address once you get notice
//Also - note that we are running the version of Standalone from Zulucrypto and not
//the Stellar foundation's quickstart
//The protocol defaults to HTTP hence the allowHttp parameter has to be set true
StellarSdk.Network.use(new StellarSdk.Network("Standalone World Wire Network ; Mar 2019"));
var server = new StellarSdk.Server('http://34.80.67.4:1234', {allowHttp: true});

//This instantiates newPart as the keypair to fund with Stellar lumens
//We will use the passed in parameter, which is a string of length 56, 
//starting with G if it is a valid Stellar public address
//Otherwise, we will generate a random keypair and fund that instead
var randoAcct = StellarSdk.Keypair.random();
var newAcctAddr = "";
var secKey = "unknown";
var amount = "888.88";

if ( (process.argv.length > 2) && (process.argv[2].length == 56) && (process.argv[2].charAt(0) == "G")){
  newAcctAddr = process.argv[2];
}else{
  newAcctAddr = randoAcct.publicKey();
  secKey = randoAcct.secret();
}

if (process.argv.length > 3){
  amount = process.argv[3];
}

//Actual work done
fundMe(newAcctAddr, secKey);

//This is the function that funds the account
function fundMe(newAcctAddr,secKey){
    var memo = StellarSdk.Memo.text("Create account");
    let keypair = StellarSdk.Keypair.master();
    console.log("Master public addr:",keypair.publicKey());
    console.log("Secret master:",keypair.secret());
      server.loadAccount(keypair.publicKey()).then((source) => {

        let tx = new StellarSdk.TransactionBuilder(source, {
		memo: memo,
		fee: 100
	})
          .addOperation(
            StellarSdk.Operation.createAccount({
              destination: newAcctAddr,
              startingBalance: amount
            })
          )
          .setTimeout(20) //This is mandatory now in the latest Stellar JS SDK release (something past v10)
          .build();

        tx.sign(keypair);

        server
          .submitTransaction(tx)
          .catch((error) => {
            errorCB(error);
            done();
          });
          success(newAcctAddr, secKey);
      });
}

//This prints the error message if we failed
function errorCB(error){
  console.log("We failed for some reason to fund the account");
	console.error("Horizon's error message was:\n",error);
}

//This prints the success message if we were successful
//Function waits until the completion of the creation and funding process
function success(publicKey,secretKey){
	console.log("We have funded this account:");
	console.log(publicKey);
	console.log(secretKey);
}
