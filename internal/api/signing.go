package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"

	"github.com/yaronf/httpsign"
)

func hexPrivKeyToECDSA(hexPrivKey string) ecdsa.PrivateKey {
	d := new(big.Int)
	d.SetString(hexPrivKey, 16)

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: d,
	}
	priv.X, priv.Y = priv.ScalarBaseMult(priv.D.Bytes())
	return *priv
}

func signRequest(hexPrivKey string, req *http.Request) error {
	priv := hexPrivKeyToECDSA(hexPrivKey)
	pub := priv.PublicKey

	pubStr := hex.EncodeToString(pub.X.Bytes()) + hex.EncodeToString(pub.Y.Bytes())
	h := sha256.Sum256([]byte(pubStr))
	fingerprint := hex.EncodeToString(h[:])

	fields := httpsign.Headers("@method", "content-digest")
	signer, _ := httpsign.NewP256Signer(priv, nil, fields)

	req.Header.Set("X-Fingerprint", fingerprint)

	digest, err := httpsign.GenerateContentDigestHeader(&req.Body, []string{httpsign.DigestSha256})
	if err != nil {
		return fmt.Errorf("could not generate content digest: %w", err)
	}
	req.Header.Set("Content-Digest", digest)

	sigInput, sig, err := httpsign.SignRequest("sig77", *signer, req)
	if err != nil {
		return fmt.Errorf("could not sign request: %w", err)
	}

	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)
	return nil
}
