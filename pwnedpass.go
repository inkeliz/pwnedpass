package pwnedpass

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Client is used to retrieve information from https://haveibeenpwned.com API.
type Client struct {
	// DisablePadding if true will disable the padding.
	DisablePadding bool
	// MaxSize limits the maximum body/content length.
	MaxSize int64
	// UserAgent sets the UA header used to connect to API.
	UserAgent string
	// HTTPClient holds the http.Client used to create the connection.
	HTTPClient http.Client
}

// Compromised returns how many times the given password was found,
// based on https://haveibeenpwned.com/API/v3#PwnedPasswords.
// The matches will be zero if the password is not found or
// an error occur.
func (c *Client) Compromised(password []byte) (matches int, err error) {
	h := sha1.New()
	h.Write(password)

	hash := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	prefix, suffix := hash[:5], hash[5:]

	req, _ := http.NewRequest(http.MethodGet, "https://api.pwnedpasswords.com/range/"+prefix, nil)
	if !c.DisablePadding {
		req.Header.Set("Add-Padding", "true")
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if runtime.GOOS == "JS" {
		req.Header.Set("js.fetch:mode", "cors")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	body := io.Reader(resp.Body)
	if c.MaxSize > 0 {
		body = io.LimitReader(resp.Body, c.MaxSize)
	}

	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), ":")
		if len(line) <= 0 {
			return 0, errors.New("invalid response")
		}
		if line[0] == suffix && line[1] != "0" {
			i, err := strconv.Atoi(line[1])
			if err != nil {
				matches = 1
			}
			matches = i
		}
	}

	if err = scanner.Err(); err != nil {
		return 0, err
	}

	return matches, nil
}

// IsCompromised returns true if the given password is already known/leaked,
// based on https://haveibeenpwned.com/API/v3#PwnedPasswords.
func (c *Client) IsCompromised(password []byte) (bool, error) {
	i, err := c.Compromised(password)
	if err != nil {
		return false, err
	}
	return i > 0, nil
}

// DefaultClient is the default client, used for IsCompromised and
// Compromised function.
var DefaultClient = &Client{
	DisablePadding: false,
	MaxSize:        1<<26,
	UserAgent:      "inkeliz/pwnedpass",
	HTTPClient: http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				CipherSuites:     []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_256_GCM_SHA384},
				MinVersion:       tls.VersionTLS13,
				CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP384, tls.CurveP256},
			},
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  5 * time.Second,
		},
		Timeout: 10 * time.Second,
	},
}

// Compromised uses DefaultClient.Compromised.
func Compromised(password []byte) (int, error) {
	return DefaultClient.Compromised(password)
}

// IsCompromised uses DefaultClient.IsCompromised.
func IsCompromised(password []byte) (bool, error) {
	return DefaultClient.IsCompromised(password)
}
