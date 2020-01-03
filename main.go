package main

import (
  "bytes"
  "encoding/binary"
  "errors"
  "fmt"
  "github.com/btcsuite/btcd/btcec"
  "github.com/btcsuite/btcd/chaincfg/chainhash"
  "github.com/btcsuite/btcutil/base58"
  "github.com/btcsuite/btcutil/hdkeychain"
  "github.com/urfave/cli"
  "math/big"
  "os"
  "strings"
)

// https://jlopp.github.io/xpub-converter/

var versions = map[string][]byte{
  "xpub": {0x04, 0x88 ,0xb2, 0x1e},
  "ypub": {0x04, 0x9d, 0x7c, 0xb2},
  "tpub": {0x04, 0x35, 0x87, 0xcf},
  "zpub": {0x04, 0xb2, 0x47, 0x46},
  "upub": {0x04, 0x4a, 0x52, 0x62},
  "vpub": {0x04, 0x5f, 0x1c, 0xf6},
  "Ypub": {0x02, 0x95, 0xb4, 0x3f},
  "Zpub": {0x02, 0xaa, 0x7e, 0xd3},
  "Upub": {0x02, 0x42, 0x89, 0xef},
  "Vpub": {0x02, 0x57, 0x54, 0x83},
}

func main() {

  var app = cli.NewApp()
  app.Commands = []cli.Command{}

  initCommands( app )

  err := app.Run(os.Args)
  if err != nil {
    println( err.Error() )
  }
}

func initCommands( app *cli.App ) {
  app.Commands = append( app.Commands, []cli.Command{
    {
      Name:    "convert",
      Aliases: []string{"c"},
      Usage:   "converts",
      Action: action_Convert,
    },
  }...
  )
}

func action_Convert( c *cli.Context ) error {
  // TODO: upgrade without removal
  if len(c.Args()) == 0 {
    return errors.New("nothing to convert")
  }
  var target string
  if len(c.Args()) < 2 {
    target = "xpub"
  } else {
    target = strings.Trim( c.Args().Get(1), " \n")
  }

  pub32String := strings.Trim( c.Args().Get(0), " \n")
  xpub32, err := convertKey(pub32String, target)

  fmt.Printf( "Converting %s to %s\n", pub32String, target )

  if err != nil {
    return err
  }

  println( xpub32.String() )
  return nil
}

// convertKey returns a new extended key instance from a base58-encoded
// extended key.
const serializedKeyLen = 4 + 1 + 4 + 4 + 32 + 33 // 78 bytes

func convertKey(key string, target string) (*hdkeychain.ExtendedKey, error) {
  // The base58-decoded extended key must consist of a serialized payload
  // plus an additional 4 bytes for the checksum.
  var version []byte
  var found bool
  if version, found = versions[target]; !found {
    return nil, errors.New("no such target key type")
  }

  decoded := base58.Decode(key)
  if len(decoded) != serializedKeyLen+4 {
    return nil, errors.New("invalid key length")
  }

  // The serialized format is:
  //   version (4) || depth (1) || parent fingerprint (4)) ||
  //   child num (4) || chain code (32) || key data (33) || checksum (4)

  // Split the payload and checksum up and ensure the checksum matches.
  payload := decoded[:len(decoded)-4]
  checkSum := decoded[len(decoded)-4:]
  expectedCheckSum := chainhash.DoubleHashB(payload)[:4]
  if !bytes.Equal(checkSum, expectedCheckSum) {
    return nil, errors.New("bad checksum")
  }

  // Deserialize each of the payload fields.
  depth := payload[4:5][0]
  parentFP := payload[5:9]
  childNum := binary.BigEndian.Uint32(payload[9:13])
  chainCode := payload[13:45]
  keyData := payload[45:78]

  // The key data is a private key if it starts with 0x00.  Serialized
  // compressed pubkeys either start with 0x02 or 0x03.
  isPrivate := keyData[0] == 0x00
  if isPrivate {
    // Ensure the private key is valid.  It must be within the range
    // of the order of the secp256k1 curve and not be 0.
    keyData = keyData[1:]
    keyNum := new(big.Int).SetBytes(keyData)
    if keyNum.Cmp(btcec.S256().N) >= 0 || keyNum.Sign() == 0 {
      return nil, errors.New("unusable seed")
    }
  } else {
    // Ensure the public key parses correctly and is actually on the
    // secp256k1 curve.
    _, err := btcec.ParsePubKey(keyData, btcec.S256())
    if err != nil {
      return nil, err
    }
  }

  return hdkeychain.NewExtendedKey(version, keyData, chainCode, parentFP, depth,
    childNum, isPrivate), nil
}
