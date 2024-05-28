package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

// fetchPage fetches the content of a webpage
func fetchPage(url string) (string, error) {
	res, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("error fetching page %s: %v", url, err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body for page %s: %v", url, err)
	}

	return string(body), nil
}
