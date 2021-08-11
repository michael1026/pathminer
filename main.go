package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/michael1026/pathminer/util"
)

func main() {
	var wordlist []string
	wg := &sync.WaitGroup{}
	urlMap := make(map[string]struct{})
	extensions := []string{""}

	wordlistFile := flag.String("w", "", "Wordlist file")
	extensionsList := flag.String("e", "", "Comma separated list of extensions. Extends FUZZ keyword.")
	threads := flag.Int("t", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")

	flag.Parse()

	if *wordlistFile != "" {
		wordlist, _ = readWordlistIntoFile(*wordlistFile)
	}

	if *extensionsList != "" {
		extensionsSplit := util.SplitByCharAndTrimSpace(*extensionsList, ",")
		for _, ext := range extensionsSplit {
			extensions = util.AppendIfMissing(extensions, ext)
		}
	}

	client := buildHttpClient()
	urlsToFuzz := make(chan string)

	s := bufio.NewScanner(os.Stdin)

	for i := 0; i < *threads; i++ {
		wg.Add(1)

		go func() {
			for rawUrl := range urlsToFuzz {
				findPaths(rawUrl, &wordlist, &extensions, client)
			}
			wg.Done()
		}()
	}

	for s.Scan() {
		urlToAdd, _ := url.Parse(s.Text())
		urlToAdd, _ = url.Parse(urlToAdd.Scheme + "://" + urlToAdd.Host + urlToAdd.Path)
		wordlist = wordsFromURL(wordlist, urlToAdd.Path)
		root := urlToAdd.Scheme + "://" + urlToAdd.Host + "/"

		ext := grabExtension(urlToAdd.Path)
		if ext != "" {
			extensions = util.AppendIfMissing(extensions, ext)
		}

		if urlToAdd.Path == "" {
			urlToAdd.Path = "/"
		}

		for root != urlToAdd.String() {
			urlToAdd.Path = path.Dir(urlToAdd.Path)
			if _, ok := urlMap[urlToAdd.String()]; !ok {

				urlsToFuzz <- urlToAdd.String()
				urlMap[urlToAdd.String()] = struct{}{}
			}
		}

		if _, ok := urlMap[urlToAdd.String()]; !ok {
			urlsToFuzz <- urlToAdd.String()
			urlMap[urlToAdd.String()] = struct{}{}
		}
	}

	close(urlsToFuzz)

	wg.Wait()
}

func findPaths(rawUrl string, wordlist *[]string, extensions *[]string, client *http.Client) {
	parsedUrl, _ := url.Parse(rawUrl)
	preStatusParsed, _ := url.Parse(rawUrl)
	preStatusParsed.Path = path.Join(preStatusParsed.Path, util.RandSeq(5))
	preStatus, _ := getStatus(client, preStatusParsed.String())

	if preStatus != http.StatusOK {
		for _, word := range *wordlist {
			for _, ext := range *extensions {
				newUrl, _ := url.Parse(rawUrl)
				newPath := path.Join(parsedUrl.Path, word+ext)
				newUrl.Path = newPath
				status, redirect := getStatus(client, newUrl.String())

				if status == http.StatusOK {
					if ext == "" {
						fmt.Println(newUrl.String())
						continue
					}
					wildcardTestUrl, _ := url.Parse(rawUrl)
					wildcardTestUrl.Path = path.Join(wildcardTestUrl.Path, word+"."+util.RandSeq(4))

					// if something like example.php was a 200, but so is example.xyz, then we're ignoring the original
					if wildcardStatus, _ := getStatus(client, wildcardTestUrl.String()); wildcardStatus == http.StatusOK {
						continue
					}

					fmt.Println(newUrl.String())
				}

				if status == http.StatusMovedPermanently && redirect == newUrl.String()+"/" {
					status, _ := getStatus(client, redirect)

					if status == http.StatusOK {
						fmt.Println(redirect)
					}

					findPaths(newUrl.String(), wordlist, extensions, client)
				}
			}
		}
	}
}

func GetRedirectLocation(resp *http.Response, absolute bool) string {

	redirectLocation := ""
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		if loc, ok := resp.Header["Location"]; ok {
			if len(loc) > 0 {
				redirectLocation = loc[0]
			}
		}
	}

	if absolute {
		redirectUrl, err := url.Parse(redirectLocation)
		if err != nil {
			return redirectLocation
		}
		location, _ := resp.Location()
		if location != nil {
			baseUrl, err := url.Parse(location.String())
			if err != nil {
				return redirectLocation
			}
			redirectLocation = baseUrl.ResolveReference(redirectUrl).String()
		}
	}

	return redirectLocation
}

func wordsFromURL(words []string, url string) []string {
	regex := "[A-Za-z]+"

	re := regexp.MustCompile(regex)

	matches := re.FindAllStringSubmatch(url, -1)

	for _, match := range matches {
		words = util.AppendIfMissing(words, match[0])
	}

	return words
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = util.AppendIfMissing(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func readWordlistIntoFile(wordlistPath string) ([]string, error) {
	lines, err := readLines(wordlistPath)
	if err != nil {
		log.Fatalf("readLines: %s", err)
	}
	return lines, err
}

func buildHttpClient() (c *http.Client) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Duration(time.Duration(10) * time.Second),
		Transport: &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 500,
			MaxConnsPerHost:     500,
			DialContext: (&net.Dialer{
				Timeout: time.Duration(time.Duration(10) * time.Second),
			}).DialContext,
			TLSHandshakeTimeout: time.Duration(time.Duration(10) * time.Second),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Renegotiation:      tls.RenegotiateOnceAsClient,
				ServerName:         "",
			},
		}}

	return client
}

func getStatus(client *http.Client, url string) (int, string) {

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return -1, ""
	}

	req.Header.Add("Connection", "close")
	req.Header.Set("User-Agent", "SomeGoProgram")
	req.Close = true

	resp, err := client.Do(req)
	if resp != nil {
		io.Copy(ioutil.Discard, resp.Body)
	}

	if err != nil {
		return -1, ""
	}

	resp.Body.Close()

	redirectUrl := GetRedirectLocation(resp, false)

	return resp.StatusCode, redirectUrl
}

func grabExtension(path string) string {
	extensions :=
		[]string{".php", ".jsp", ".asp", ".aspx",
			".cgi", ".cfm", ".do", ".go", ".action",
			".axd", ".asmx", ".asx", ".ashx", ".aspx",
			".phtml", ".xhtml"}

	for _, ext := range extensions {
		if strings.HasSuffix(path, ext) {
			return ext
		}
	}
	return ""
}
