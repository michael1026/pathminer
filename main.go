package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sync"
	"time"

	"github.com/michael1026/pathminer/util"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

func main() {
	// read urls from stdin - Done
	// generate wordlist from supplied urls - Done
	// fuzz using generated + user supplied wordlist - Done
	// with extension on last path (/xxx/yyy/FUZZ.php)
	// without extension on last path (/xxx/yyy/FUZZ) - Done
	// remove path and try again (/xxx/FUZZ.php, /xxx/FUZZ, /FUZZ.php, /FUZZ) - Done
	// follow 301 redirect (/xxx -> /xxx/) and add this to list of urls to fuzz - Done
	// would be nice to detect duplicates when removing paths - Done

	var wordlist []string
	wg := &sync.WaitGroup{}
	urlMap := make(map[string]struct{})

	wordlistFile := flag.String("w", "", "Wordlist file")
	threads := flag.Int("t", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")

	flag.Parse()

	if *wordlistFile != "" {
		wordlist, _ = readWordlistIntoFile(*wordlistFile)
	}

	client := buildHttpClient()
	urlsToFuzz := make(chan string)

	s := bufio.NewScanner(os.Stdin)

	for i := 0; i < *threads; i++ {
		wg.Add(1)

		go func() {
			for rawUrl := range urlsToFuzz {
				findPaths(rawUrl, &wordlist, client)
			}
			wg.Done()
		}()
	}

	for s.Scan() {
		urlToAdd, _ := url.Parse(s.Text())
		urlToAdd, _ = url.Parse(urlToAdd.Scheme + "://" + urlToAdd.Host + urlToAdd.Path)
		wordlist = wordsFromURL(wordlist, urlToAdd.Path)
		root := urlToAdd.Scheme + "://" + urlToAdd.Host + "/"

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

func findPaths(rawUrl string, wordlist *[]string, client *http.Client) {
	parsedUrl, _ := url.Parse(rawUrl)
	for _, word := range *wordlist {
		newUrl, _ := url.Parse(rawUrl)
		path := path.Join(parsedUrl.Path, word)
		newUrl.Path = path
		status, redirect := getStatus(client, newUrl.String())

		if status == http.StatusOK {
			fmt.Println(newUrl.String())
		}

		if status == http.StatusMovedPermanently && redirect == newUrl.String()+"/" {
			findPaths(newUrl.String(), wordlist, client)
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

func fuzzPath(url string) {

}

func fuzzPathWithExt(url string, ext string) {

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
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		return
	}

	transport := &http.Transport{
		MaxIdleConns:      100,
		IdleConnTimeout:   time.Second * 10,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext:       dialer.Dial,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := &http.Client{
		Transport:     transport,
		CheckRedirect: re,
		Timeout:       time.Second * 10,
	}

	return client
}

func getStatus(client *http.Client, url string) (int, string) {

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return -1, ""
	}

	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := client.Do(req)
	if resp != nil {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}

	if err != nil {
		return -1, ""
	}

	redirectUrl := GetRedirectLocation(resp, true)

	return resp.StatusCode, redirectUrl
}
