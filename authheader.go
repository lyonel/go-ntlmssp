package ntlmssp

import (
	"encoding/base64"
	"errors"
	"strings"
)

type AuthHeader string

func (h AuthHeader) IsBasic() bool {
	return h.GetType() == "Basic"
}

func (h AuthHeader) IsNegotiate() bool {
	return h.GetType() == "Negotiate"
}

func (h AuthHeader) IsNTLM() bool {
	return h.GetType() == "NTLM"
}

func (h AuthHeader) GetType() string {
	p := strings.Split(string(h), " ")
	if len(p) < 2 {
		return string(h)
	}
	return string(p[0])
}

func (h AuthHeader) GetData() ([]byte, error) {
	p := strings.Split(string(h), " ")
	if len(p) < 2 {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(string(p[1]))
}

func (h AuthHeader) GetBasicCreds() (username, password string, err error) {
	if h.GetType() != "Basic" {
		return "", "", errors.New("Wrong authentication type")
	}
	if d, err := h.GetData(); err != nil {
		return "", "", err
	} else {
		if parts := strings.SplitN(string(d), ":", 2); len(parts) == 2 {
			return parts[0], parts[1], nil
		} else {
			return "", "", errors.New("Invalid authentication data")
		}
	}
}
