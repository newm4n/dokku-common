package dokku_common

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/SermoDigital/jose/crypto"
	"github.com/newm4n/dokku-common/security"
	"github.com/sirupsen/logrus"
	"net/http"
)

type ContextKey string

var (
	UserAuthorization ContextKey      = "USER_AUTHORIZATION"
	UserClaim         ContextKey      = "USER_CLAIM"
	privateKey        *rsa.PrivateKey = nil
	publicKey         *rsa.PublicKey  = nil

	ErrBearerTokenInvalid = fmt.Errorf("invalid bearer token")
)

const (
	DefaultPrivatePEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQEAsZ6vq7T+E6UnFHf1i5wljs4c+dpXTsIa1fk6S6Z74v/V7AjW
qXzJ52aI+N18yf+PD4HuZN/AvDOqIjQgaGUJH9W5F4Ppz1dNIJBU5qYsJOEwIl1/
uRkBPtKPRtYESVbYPPU6va7ttZv0lZEvPpJ1l+axo5ULaBnWW0IJqYipMU58IlVR
c+sJEV0sC4vvPHk62/VixpjskHuGeD0fmNu8U+cnv7wav+N/2G4hSgakYJofhkx+
watP2wHBCrSDMq8rc4socdWebmISQhoCkwI/Gr1F29l4A1wGjQt0oA3eTATFng+j
D0MLmR3lP7elATNTmHawpBH6IqWX9eKVSJ8M9wIDAQABAoIBAAnuJUQkSlAu25B5
ZHD5ud/SBiyx2E++6mEsHeY82JBIXV1k4Rt4rpERWncPavqgHw9u5DUfjVb4THq9
D1LG00vEVyTJazj8WIOJjjWW9MDbFiXVtF5U14z7mKcNMBApms1NqIsSTJfqsDHs
fAeziH+Flkje/FRFnYZcms2vpkXrVUd191Rr2Zwc0m8vLroAq5LGE9uFbNM5z1mL
FTUaESnQdNf+Pg6It9p/eJ+jXbN98dbNCd2xObD+LrPLeSMpy2o41Bqk6vLN7pwN
zI5jGMgaIC7SHZHiU5O+mnsbQ2kBknubXgKxm6SuaVp13TCd9tNW7Wu74MznUJ3T
AQsZeoECgYEA+Ay0grNBnNWTejg20zVexO4t3etvd+NpHu268kIf87L9NX16hYAd
IZvAXzlu0Y0hzA9SA/xygtTXdm6HZhl+4VFjLfLwudVVLFPf2RqinJdyrI6lbgE9
ksUBpFL2dtzCmPQ70Rj791u9Ai1k6/zh6XqDL0ITAg70KrL5iDHmWVUCgYEAt1AX
Y9Nxqkeiq2WqN1VmFqqW/FwwsqybuggaTKCQ3Zj5sNR8aMIYpY7kUTf/+Xk5Wdcy
VAMMr824SVqgeNyd8YnTIn9htRs5g/moO5+GQrVk2YPR6m1x6drj7c5d74VEubdk
ech4Yg25Vra1roC+cvgZdgSPa7mxmZ5TVMRhHRsCgYEAy2wP9UfwvR/iLE9BlwCj
0bjK4L4d0iIrqXOo5tgXwBG/2kgnXKhuO4uxveYp3axyVRkTV7WGa4kFklierbqm
9T17qskbZitwCERYxYE0bls9bgol3QsjZeQuroZjHaN561oQXDCzIm6XmNuFcosW
8hTI1M7JK9z7nLDeNzVFBWkCgYAls7RL1MYw9nDPfaZnoQnRKZ7KIo/lf7i7p0T5
c6C34umf4+P+i8UT7/KnfbQI9FTGVItGWiY21kHL3HbaxM07S1SAaOCIpiPLMALY
2HN9rt8iGYmIBKCEL3/nfiU1yRwcckqY/ZE84YO4APYXAOWqsbpS2pdA2b1cUgLj
kUxD9wJ/BrLnevv6y7BA/oOsf5yl9WvgCaYgFKiUxTwgZmjDP/W36HYDV9is8MwQ
9VRjLLMXN1p/UYxNjFJlUJwjLMmGcKR9rVtJxFI+I65I1wrCGl9A8vsyS/oKZVKy
hMmtM9D7v/lK/yBAJzHLA7QD+EiDuEk26Xob30B7mk5PuNLRDQ==
-----END RSA PRIVATE KEY-----`
	DefaultPublicPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsZ6vq7T+E6UnFHf1i5wl
js4c+dpXTsIa1fk6S6Z74v/V7AjWqXzJ52aI+N18yf+PD4HuZN/AvDOqIjQgaGUJ
H9W5F4Ppz1dNIJBU5qYsJOEwIl1/uRkBPtKPRtYESVbYPPU6va7ttZv0lZEvPpJ1
l+axo5ULaBnWW0IJqYipMU58IlVRc+sJEV0sC4vvPHk62/VixpjskHuGeD0fmNu8
U+cnv7wav+N/2G4hSgakYJofhkx+watP2wHBCrSDMq8rc4socdWebmISQhoCkwI/
Gr1F29l4A1wGjQt0oA3eTATFng+jD0MLmR3lP7elATNTmHawpBH6IqWX9eKVSJ8M
9wIDAQAB
-----END PUBLIC KEY-----`
)

func RequestMayThrough(request *http.Request, tenant, role string) bool {
	if request == nil || len(tenant) == 0 || len(role) == 0 {
		return false
	}
	if goClaim, ok := request.Context().Value(UserClaim).(*security.GoClaim); ok {
		for _, aud := range goClaim.Audience {
			tr, err := security.NewTenantRole(aud)
			if err != nil {
				logrus.Debugf("error while creating tenant-role got %s", err.Error())
				continue
			}
			if tr.Validates(tenant, role) {
				return true
			}
		}
	}
	return false
}

func UserTokenContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		AuthHeader := r.Header.Get("Authorization")
		if len(AuthHeader) > 0 {
			if len(AuthHeader) < 7 {
				w.Header().Add("Content-Type", "text/plain")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Authorization header found, but it seems that it uses wrong bearer string"))
				return
			}
			if GetPublicKey(nil) == nil {
				w.Header().Add("Content-Type", "text/plain")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Authorization header found, but public key for verification is not configured"))
				return
			}
			goClaim, err := security.NewGoClaimFromToken(AuthHeader[7:], GetPublicKey(nil), crypto.SigningMethodRS512)
			if err != nil {
				w.Header().Add("Content-Type", "text/plain")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(fmt.Sprintf("Authorization header found, but token contains problem. %s", err.Error())))
				return
			}
			nCtx := context.WithValue(r.Context(), UserAuthorization, AuthHeader)
			nCtx = context.WithValue(nCtx, UserClaim, goClaim)
			next.ServeHTTP(w, r.WithContext(nCtx))
		}
		next.ServeHTTP(w, r)
	})
}

func WriteHttpResponse(response http.ResponseWriter, status int, headers map[string][]string, body []byte) {
	if status != http.StatusOK {
		if body == nil {
			logrus.Warnf("[%d]", status)
		} else {
			logrus.Warnf("[%d] %s", status, string(body))
		}
	}
	if headers != nil {
		for headerKey, headerValueArray := range headers {
			for _, headerValue := range headerValueArray {
				response.Header().Add(headerKey, headerValue)
			}
		}
	}
	response.WriteHeader(status)
	if body != nil {
		response.Write(body)
	}
}

func GetPrivateKey(privateKeyPEM []byte) *rsa.PrivateKey {
	if privateKey != nil {
		return privateKey
	}
	if privateKeyPEM != nil {
		if priKey, err := security.BytesToPrivateKey(privateKeyPEM); err == nil {
			privateKey = priKey
			return privateKey
		}
	}
	logrus.Errorf("Can not load private key from file, using default private key. THIS IS NOT SAVE")
	priKey, err := security.BytesToPrivateKey([]byte(DefaultPrivatePEM))
	if err != nil {
		fmt.Println(DefaultPrivatePEM)
		panic(err)
	}
	privateKey = priKey
	return privateKey
}

func GetPublicKey(publicKeyPEM []byte) *rsa.PublicKey {
	if publicKey != nil {
		fmt.Println("Gobal variable publicKey is not nil")
		return publicKey
	}
	if publicKeyPEM != nil {
		if pubKey, err := security.BytesToPublicKey(publicKeyPEM); err == nil {
			publicKey = pubKey
			return publicKey
		}
	}
	logrus.Error("Can not load public key from file, using default public key. THIS IS NOT SAVE")
	pubKey, err := security.BytesToPublicKey([]byte(DefaultPublicPEM))
	if err != nil {
		panic(err)
	}
	publicKey = pubKey
	return publicKey
}
