package main

import (
	"fmt"

	b "github.com/stellar/go/build"
	"github.com/stanleyyong/go/clients/horizon"
	"github.com/stanleyyong/go/network"
)

func main() {
	// address: GB6S3XHQVL6ZBAF6FIK62OCK3XTUI4L5Z5YUVYNBZUXZ4AZMVBQZNSAU
	from := "SCRUYGFG76UPX3EIUWGPIQPQDPD24XPR3RII5BD53DYPKZJGG43FL5HI"

	// seed: SDLJZXOSOMKPWAK4OCWNNVOYUEYEESPGCWK53PT7QMG4J4KGDAUIL5LG
	to := "GA3A7AD7ZR4PIYW6A52SP6IK7UISESICPMMZVJGNUTVIZ5OUYOPBTK6X"

	passphrase := network.WWNetworkPassphrase

	tx, err := b.Transaction(
		b.Network{passphrase},
		b.SourceAccount{from},
		b.AutoSequence{horizon.DefaultWWNetClient},
		b.Payment(
			b.Destination{to},
			b.NativeAmount{"3.14127"},
		),
	)

	if err != nil {
		panic(err)
	}

	txe, err := tx.Sign(from)
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
}
