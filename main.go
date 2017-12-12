package main

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"crypto"
	"crypto/rand"
	"crypto/x509"

	"github.com/urfave/cli"
	"github.com/vbatts/go-mtree"

	"pault.ag/go/ima"
)

func Main(c *cli.Context) error {
	key, err := LoadKey(c)
	if err != nil {
		return err
	}

	for _, arg := range c.Args() {
		if err := os.MkdirAll(filepath.Dir(c.GlobalString("output")), 0755); err != nil {
			return err
		}

		dh, err := SignTree(key, rand.Reader, crypto.SHA256, arg)
		if err != nil {
			return err
		}

		fd, err := os.Create(c.GlobalString("output"))
		if err != nil {
			return err
		}
		defer fd.Close()

		if _, err := dh.WriteTo(fd); err != nil {
			return err
		}
	}
	return nil
}

func LoadKey(c *cli.Context) (crypto.Signer, error) {
	fd, err := os.Open(c.GlobalString("privkey"))
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func SignTree(signer crypto.Signer, entropy io.Reader, hashFunc crypto.Hash, root string) (*mtree.DirectoryHierarchy, error) {
	dh := mtree.DirectoryHierarchy{}

	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if !info.Mode().IsRegular() {
			return nil
		}

		entry, err := SignFile(signer, entropy, hashFunc, root, path)
		if err != nil {
			return err
		}
		dh.Entries = append(dh.Entries, *entry)
		return nil
	}); err != nil {
		return nil, err
	}
	return &dh, nil
}

func SignFile(signer crypto.Signer, entropy io.Reader, hashFunc crypto.Hash, root, path string) (*mtree.Entry, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	hash := hashFunc.New()

	_, err = io.Copy(hash, fd)
	if err != nil {
		return nil, err
	}

	digest := hash.Sum(nil)
	sig, err := ima.Sign(signer, entropy, digest, hashFunc)
	if err != nil {
		return nil, err
	}

	relPath, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}

	return &mtree.Entry{
		Name: relPath,
		Keywords: []mtree.KeyVal{
			mtree.KeyVal(fmt.Sprintf("xattr.security.ima=%s", base64.StdEncoding.EncodeToString(sig))),
		},
	}, nil
}

func main() {
	app := cli.NewApp()
	app.Name = "ima-mtree-sign"
	app.Usage = "ima-mtree-sign [path]"
	app.Action = Main
	app.Flags = []cli.Flag{
		cli.StringFlag{Name: "privkey"},
		cli.StringFlag{Name: "output", Value: "mtree"},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
