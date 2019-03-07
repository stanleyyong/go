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

//modifying to allow setops
var rootkeypair = StellarSdk.Keypair.fromSecret("SBRSUFA3OIW436UB3EKKHE6YWF7SFALGWUO44IWRWXFPL26WQMK5M2BN")
var account = new StellarSdk.Account(rootkeypair.publicKey(), "124339303219200"); //what is this number

var secondaryAddress = "GBINH3WY5VQHVPH3755QVMQKPSFVTF6T7NZAVDWU2OFCZ5PD6RFAZN3R";

var transaction = new StellarSdk.TransactionBuilder(account, {
    fee: StellarSdk.BASE_FEE
  })
  /*.addOperation(StellarSdk.Operation.setOptions({
    signer: {
      ed25519PublicKey: secondaryAddress,
      weight: 1
    }
  }))*/
  .addOperation(StellarSdk.Operation.setOptions({
    masterWeight: 1, // set master key weight
    lowThreshold: 1,
    medThreshold: 2, // a payment is medium threshold
    highThreshold: 2 // make sure to have enough weight to add up to the high threshold!
  }))
  .setTimeout(30)
  .build();

transaction.sign(rootkeypair); // only need to sign with the root signer as the 2nd signer won't be added to the account till after this transaction completes

server
          .submitTransaction(transaction)
          .catch((error) => {
            errorCB(error);
            done();
        });

// now create a payment with the account that has two signers

var transaction = new StellarSdk.TransactionBuilder(account, {
      fee: StellarSdk.BASE_FEE
    })
    .addOperation(StellarSdk.Operation.payment({
        destination: "GBTVUCDT5CNSXIHJTDHYSZG3YJFXBAJ6FM4CKS5GKSAWJOLZW6XX7NVC",
        asset: StellarSdk.Asset.native(),
        amount: "2000" // 2000 XLM
    }))
    .setTimeout(30)
    .build();

var secondKeypair = StellarSdk.Keypair.fromSecret("SAMZUAAPLRUH62HH3XE7NVD6ZSMTWPWGM6DS4X47HLVRHEBKP4U2H5E7");

// now we need to sign the transaction with both the root and the secondaryAddress
transaction.sign(rootkeypair);
transaction.sign(secondKeypair);

function errorCB(error){
    console.log("We failed for some reason to fund the account");
      console.error("Horizon's error message was:\n",error);
  }