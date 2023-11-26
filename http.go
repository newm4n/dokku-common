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
	PrivateKey        *rsa.PrivateKey = nil
	PublicKey         *rsa.PublicKey  = nil

	ErrBearerTokenInvalid = fmt.Errorf("invalid bearer token")
)

func RequestMayThrough(request *http.Request, tenant, role string) bool {
	if request == nil || len(tenant) == 0 || len(role) == 0 {
		return false
	}
	if goClaim, ok := request.Context().Value(UserClaim).(*security.GoClaim); ok {
		for _, aud := range goClaim.Audience {
			tr, err := security.NewTenantRole(aud)
			if err != nil {
				logrus.Debugf("error while creating tenant-role got ", err.Error())
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
			if PublicKey == nil {
				w.Header().Add("Content-Type", "text/plain")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Authorization header found, but public key for verification is not configured"))
				return
			}
			goClaim, err := security.NewGoClaimFromToken(AuthHeader[7:], PublicKey, crypto.SigningMethodRS512)
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
