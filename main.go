package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/michael1026/pathminer/util"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

func main() {
	// read urls from stdin
	// generate wordlist from supplied urls
	// fuzz using generated + user supplied wordlist
	// with extension on last path (/xxx/yyy/FUZZ.php)
	// without extension on last path (/xxx/yyy/FUZZ)
	// remove path and try again (/xxx/FUZZ.php, /xxx/FUZZ, /FUZZ.php, /FUZZ)
	// follow 301 redirect (/xxx -> /xxx/) and add this to list of urls to fuzz
	// would be nice to detect duplicates when removing paths

	var wordlist []string
	wg := &sync.WaitGroup{}

	wordlistFile := flag.String("w", "", "Wordlist file")
	threads := flag.Int("t", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")
	url := flag.String("u", "", "Single URL to scan")

	flag.Parse()

	if *wordlistFile != "" {
		wordlist, _ = readWordlistIntoFile(*wordlistFile)
	}

	client := BuildHttpClient()
	urls := make(chan string)

	s := bufio.NewScanner(os.Stdin)

	for i := 0; i < *threads; i++ {
		wg.Add(1)

		go findPaths(urls, wordlist, client, wg)
	}

	for s.Scan() {
		urls <- s.Text()
	}

	if *url != "" {
		urls <- *url
	}

	close(urls)

	wg.Wait()
}

func findPaths(urls chan string, wordlist []string, client *http.Client, wg *sync.WaitGroup) {
	for rawUrl := range urls {
		wordlist = wordsFromURL(wordlist, rawUrl)
	}
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
		words = append(words, match[0])
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

func BuildHttpClient() (c *http.Client) {
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
