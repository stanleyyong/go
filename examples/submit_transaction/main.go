package main

import (
	"fmt"

	"github.com/stanleyyong/go/clients/horizon"
)

func main() {
	//blob := "AAAAAH0t3PCq/ZCAvioV7ThK3edEcX3PcUrhoc0vngMsqGGWAAAAZAA1fpcAAAABAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAANg+Af8x49GLeB3Un+Qr9ESJJAnsZmqTNpOqM9dTDnhkAAAAAAAAAAAAPQkAAAAAAAAAAASyoYZYAAABA/L7Du9hlYzCtR9F89Mp9/alkCXsq9CWuJ1Mpql+Q16fHE4P2+H62p4cx+b2YUp/fUX73ucW+RPxOgSXmeV6uBQ=="
	blob := "AAAAAH0t3PCq/ZCAvioV7ThK3edEcX3PcUrhoc0vngMsqGGWAAAAZAAASp4AAAABAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAANg+Af8x49GLeB3Un+Qr9ESJJAnsZmqTNpOqM9dTDnhkAAAAAAAAAAAHfUdwAAAAAAAAAASyoYZYAAABAtbe3Z2VfjBQbdkZhCgARL5LnHwY7vBgdiaFRSQWDKIZhm9zPAmjkNfiuf22h8hpHLNX5IRUfoGh0tjq6nzxsBg=="

	resp, err := horizon.DefaultWWNetClient.SubmitTransaction(blob)
	if err != nil {
		panic(err)
	}

	fmt.Println("transaction posted in ledger:", resp.Ledger)
}
