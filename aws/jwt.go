package aws

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

type jwk struct {
	url  string
	keys *jwKs
}

func newJWKs(endpointUrl, userPoolID string) (*jwk, error) {

	if endpointUrl == "" || userPoolID == "" {
		return nil, fmt.Errorf("endpointUrl and userPoolId is required")
	}

	url := fmt.Sprintf("%s/%v/.well-known/jwks.json", endpointUrl, userPoolID)
	j := &jwk{
		url: url,
	}
	if err := j.fetch(); err != nil {
		return nil, err
	}
	return j, nil
}

func (s *jwk) getKeyFunc() func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method. alg=%v", token.Method.Alg())
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("unexpected header. kid is required")
		}

		for i := range s.keys.Keys {
			if kid == s.keys.Keys[i].KID {
				dec, err := base64.RawURLEncoding.DecodeString(s.keys.Keys[i].E)
				if err != nil {
					return nil, err
				}
				if len(dec) < 4 {
					data := make([]byte, 4)
					copy(data[4-len(dec):], dec)
					dec = data
				}
				pubKey := &rsa.PublicKey{
					N: &big.Int{},
					E: int(binary.BigEndian.Uint32(dec[:])),
				}
				decodedN, err := base64.RawURLEncoding.DecodeString(s.keys.Keys[i].N)
				if err != nil {
					panic(err)
				}
				pubKey.N.SetBytes(decodedN)
				return pubKey, nil
			}
		}

		return nil, fmt.Errorf("key does not found")
	}
}

func (s *jwk) fetch() error {

	res, err := http.DefaultClient.Get(s.url)
	if err != nil {
		return err
	}

	defer func() {
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get jwks from %s. statusCode=%d", s.url, res.StatusCode)
	}

	var jr jwKs
	if err := json.NewDecoder(res.Body).Decode(&jr); err != nil {
		return err
	}

	s.keys = &jr
	return nil
}

type jwKs struct {
	Keys []*struct {
		Alg string `json:"alg,omitempty"`
		E   string `json:"e,omitempty"`
		KID string `json:"kid,omitempty"`
		KTY string `json:"kty,omitempty"`
		N   string `json:"n,omitempty"`
		Use string `json:"use,omitempty"`
	} `json:"keys,omitempty"`
}
