package main

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"crypto"
	"crypto/rand"
	"crypto/x509"

	"github.com/urfave/cli"
	"github.com/vbatts/go-mtree"

	"pault.ag/go/debian/control"
	"pault.ag/go/debian/deb"
	"pault.ag/go/ima"
)

func CanonicalizePath(pkg deb.Control, path string) *string {
	if !strings.HasPrefix(path, "DEBIAN") {
		return &path
	}

	var name string
	switch pkg.MultiArch {
	case "same", "allowed":
		name = fmt.Sprintf("%s:%s", pkg.Package, pkg.Architecture)
	// case "foreign":
	default:
		name = pkg.Package
	}

	base := filepath.Base(path)
	switch base {
	case "prerm", "postrm", "preinst", "postinst":
		el := filepath.Join("/var/lib/dpkg/info", fmt.Sprintf("%s.%s", name, base))
		return &el
	default:
		return nil
	}
}

func Main(c *cli.Context) error {
	fd, err := os.Open(c.GlobalString("control"))
	if err != nil {
		return err
	}
	defer fd.Close()
	pkg := deb.Control{}
	if err := control.Unmarshal(&pkg, fd); err != nil {
		return err
	}

	key, err := LoadKey(c)
	if err != nil {
		return err
	}

	dh, err := SignTree(pkg, key, rand.Reader, crypto.SHA256, c.GlobalString("root"))
	if err != nil {
		return err
	}

	fd, err = os.Create(c.GlobalString("output"))
	if err != nil {
		return err
	}
	defer fd.Close()

	if _, err := dh.WriteTo(fd); err != nil {
		return err
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

func SignTree(pkg deb.Control, signer crypto.Signer, entropy io.Reader, hashFunc crypto.Hash, root string) (*mtree.DirectoryHierarchy, error) {
	dh := mtree.DirectoryHierarchy{}

	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if !info.Mode().IsRegular() {
			return nil
		}

		entry, err := SignFile(pkg, signer, entropy, hashFunc, root, path)
		if err != nil {
			return err
		}
		if entry == nil {
			return nil
		}

		dh.Entries = append(dh.Entries, *entry)

		return nil
	}); err != nil {
		return nil, err
	}
	return &dh, nil
}

func SignFile(pkg deb.Control, signer crypto.Signer, entropy io.Reader, hashFunc crypto.Hash, root, path string) (*mtree.Entry, error) {
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

	filePath := CanonicalizePath(pkg, relPath)
	if filePath == nil {
		return nil, nil
	}

	return &mtree.Entry{
		Name: *filePath,
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
		cli.StringFlag{Name: "privkey", EnvVar: "IMA_MTREE_PRIVATE_KEY"},
		cli.StringFlag{Name: "root", Value: "."},
		cli.StringFlag{Name: "output", Value: "DEBIAN/mtree"},
		cli.StringFlag{Name: "control", Value: "DEBIAN/control"},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
