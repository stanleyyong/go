package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/stanleyyong/go/strkey"

	"github.com/stanleyyong/go/clients/horizon"
	"github.com/stanleyyong/go/network"
	b "github.com/stellar/go/build"
)

/*
More pairs to play with:

GDQJVQ22CLHRIVU5HG3EYRHMRNCMWQ7FOER65LFTBMX4HQU3BVWPAJHD
SD2DTXUTV2X3UTCQJZSW5DPFAK3G4E5A2UYZC5O3IAYW5N6K7YOZMYR5

GDJZ523KDMHVE4EDAV625XYJI7LNXUELRAVCWAR7D45Z2BSJRI4E2VVZ
SBPAKCXCKKV5F7TQABQXFY67FJGH3LPC3QOKRGMKSQWUDS5QOQMNCD2E

GD27GYQVCDRZW5PAHSQSNZY7IDRYMXN7JOK3LTACOVDXFOMDQS6KJ4ON
SB5N6KFH3CQWNB7YDCFURKGQ5WGTWB75IR6IRHUB53ZW3EYKDYIKGEZS
*/


/*
 This function would accept one string value as argument and generate SHA256 value
 key with Stellar's HashX encoding. This would be used as signer of an account.
*/
func GenerateSHA256Hash() string {
	key := getSecretPhrase()
	hasher := sha256.New()
	hasher.Write([]byte(key))

	actual, err := strkey.Encode(strkey.VersionByteHashX, hasher.Sum(nil))
	if err != nil {
		panic(err);
		//LOGGER.Fatal(err)
		return ""
	}
	return actual
}


func main() {

	iA := "GDJZ523KDMHVE4EDAV625XYJI7LNXUELRAVCWAR7D45Z2BSJRI4E2VVZ"
	iAKey := "SBPAKCXCKKV5F7TQABQXFY67FJGH3LPC3QOKRGMKSQWUDS5QOQMNCD2E"
	adminAddress := "GD27GYQVCDRZW5PAHSQSNZY7IDRYMXN7JOK3LTACOVDXFOMDQS6KJ4ON"
	//secret for the admin is: SB5N6KFH3CQWNB7YDCFURKGQ5WGTWB75IR6IRHUB53ZW3EYKDYIKGEZS

	passphrase := network.WWNetworkPassphrase

	hashkey := GenerateSHA256Hash();
	fmt.Println("Hashkey was: %s",hashkey);

	tx, err := b.Transaction(
		b.SourceAccount{iA},
		b.Network{passphrase},
		b.AutoSequence{horizon.DefaultWWNetClient},
		b.SetOptions(
			b.SetAuthRevocable(),
			b.SetAuthRequired(),
			b.SetAuthImmutable(),
			b.SetLowThreshold(LOW_THRESHOLD),
			b.SetMediumThreshold(MEDIUM_THRESHOLD),
			b.SetHighThreshold(HIGH_THRESHOLD),
			b.AddSigner(adminAddress, WW_ADMIN_WEIGHT),
			b.MasterWeight(MASTER_WEIGHT),
			b.HomeDomain("ww.account"),
		),
		/*b.SetOptions(
			b.AddSigner(hashkey, SHA_WEIGHT),
		),*/
	)

	if err != nil {
		panic(err)
	}

	txe, err := tx.Sign(iAKey)
	if err != nil {
		panic(err)
	}

	txeB64, err := txe.Base64()
	if err != nil {
		panic(err)
	}

	if err != nil {
		panic(err)
	}

	fmt.Printf("tx base64: %s", txeB64)

        blob := txeB64

        resp, err := horizon.DefaultWWNetClient.SubmitTransaction(blob)
        if err != nil {
                panic(err)
        }

        fmt.Println("transaction posted in ledger:", resp.Ledger)

}


//todo Need to get this value from HSM
func getSecretPhrase() (secret string) {
	secret = "LORAXSNUGGLEGEORGEICE"
	return
}

var (
	LOW_THRESHOLD    = uint32(1)
	MEDIUM_THRESHOLD = uint32(2)
	HIGH_THRESHOLD   = uint32(3)
	MASTER_WEIGHT    = uint32(2)
	WW_ADMIN_WEIGHT  = uint32(1)
	SHA_WEIGHT       = uint32(2)
)

