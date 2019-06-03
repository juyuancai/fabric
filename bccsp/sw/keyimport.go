/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw

import (
	"crypto/ecdsa"
	//"crypto/ecdsa"
	"crypto/rsa"
	//"crypto/x509"
	"errors"
	"fmt"
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/tjfoc/gmsm/sm2"
)

type aes256ImportKeyOptsKeyImporter struct{}

func (*aes256ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if aesRaw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	if len(aesRaw) != 32 {
		return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 32 bytes", len(aesRaw))
	}

	return &aesPrivateKey{utils.Clone(aesRaw), false}, nil
}

type hmacImportKeyOptsKeyImporter struct{}

func (*hmacImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(aesRaw) == 0 {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	return &aesPrivateKey{utils.Clone(aesRaw), false}, nil
}

type ecdsaPKIXPublicKeyImportOptsKeyImporter struct{}


// here is to get ecdsa public key from x509 certificate ,we changed to SM2 without changing this function but replace the method in utils.DERToPublicKey()
func (*ecdsaPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}
    // here is the function we have replaced to sm2 way internally,
	lowLevelKey, err := utils.DERToPublicKey(der)
	if err != nil {
	//	return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
		return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
	}

	//ecdsaPK, ok := lowLevelKey.(*ecdsa.PublicKey)
	sm2PK, ok := lowLevelKey.(*sm2.PublicKey)
	if !ok {
		//return nil, errors.New("Failed casting to ECDSA public key. Invalid raw material.")
		return nil, errors.New("Failed casting to SM2 public key. Invalid raw material.")
	}
	return &ecdsaPublicKey{sm2PK}, nil
}

type ecdsaPrivateKeyImportOptsKeyImporter struct{}

//change utils.DERToPrivateKey(der) to replace to SM2
func (*ecdsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := utils.DERToPrivateKey(der)
	if err != nil {
		//return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
		return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
	}

	//ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
	sm2SK, ok := lowLevelKey.(*sm2.PrivateKey)
	if !ok {
		//return nil, errors.New("Failed casting to ECDSA private key. Invalid raw material.")
		return nil, errors.New("Failed casting to SM2 private key. Invalid raw material.")
	}

	//return &ecdsaPrivateKey{ecdsaSK}, nil
	return &ecdsaPrivateKey{sm2SK}, nil
}

type ecdsaGoPublicKeyImportOptsKeyImporter struct{}

// change to SM2 way
func (*ecdsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	//lowLevelKey, ok := raw.(*ecdsa.PublicKey)// ecdsa way
	lowLevelKey, ok := raw.(*sm2.PublicKey)  //sm2 way
	if !ok {
		//return nil, errors.New("Invalid raw material. Expected *ecdsa.PublicKey.")
		return nil, errors.New("Invalid raw material. Expected *SM2.PublicKey.")
	}

	return &ecdsaPublicKey{lowLevelKey}, nil
}

type rsaGoPublicKeyImportOptsKeyImporter struct{}

func (*rsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *rsa.PublicKey.")
	}

	return &rsaPublicKey{lowLevelKey}, nil
}

type x509PublicKeyImportOptsKeyImporter struct {
	bccsp *CSP
}

// change this to SM2 way
func (ki *x509PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {

	/*x509Cert, ok := raw.(*x509.Certificate)//
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *x509.Certificate.")
	}

	pk := x509Cert.PublicKey

	switch pk.(type) {
	case *ecdsa.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case *rsa.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.RSAGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.RSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	default:
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
	} */
    //below is SM2 way
	x509Cert, ok := raw.(*sm2.Certificate)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected SM2 *x509.Certificate.")
	}
	pk := x509Cert.PublicKey
	ecdsaPk := pk.(*ecdsa.PublicKey)
	sm2pk := new(sm2.PublicKey)
	sm2pk.Curve = ecdsaPk.Curve
	sm2pk.X = ecdsaPk.X
	sm2pk.Y = ecdsaPk.Y

	return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
		sm2pk,
		&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
}
