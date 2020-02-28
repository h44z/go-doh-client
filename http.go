package doh

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"crypto/tls"
)

// exchangeHTTPS sends a given query to a given resolver using a DoH POST
// request as described in RFC 8484, and returns the response's body.
// Returns an error if there was an issue sending the request or reading the
// response body.
func exchangeHTTPS(q []byte, resolver string, allowInsecure bool) (a []byte, err error) {
	url := fmt.Sprintf("https://%s/dns-query", resolver)
	body := bytes.NewBuffer(q)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return
	}

	req.Header.Add("Accept", "application/dns-message")
	req.Header.Add("Content-Type", "application/dns-message")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify : allowInsecure},
	}
	client := http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("HTTPS server returned with non-OK code %d", resp.StatusCode)
		return
	}

	return ioutil.ReadAll(resp.Body)
}
