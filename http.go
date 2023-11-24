package dokku_common

import (
	"github.com/sirupsen/logrus"
	"net/http"
)

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
