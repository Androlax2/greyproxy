package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

const localAPIBaseURL = "http://localhost:43080"

// handleDashboardURL prints a single-use login link for the dashboard, signed
// with the API token so the link itself never carries the token.
func handleDashboardURL(args []string) {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: greyproxy dashboard-url")
		os.Exit(2)
	}

	token, err := greyproxy.ReadAPIToken(greyproxyDataHome())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\nIs greyproxy installed and started at least once? Check with: greyproxy service status\n", err)
		os.Exit(1)
	}

	fmt.Println(dashboardLoginURL(localAPIBaseURL, token, time.Now()))
	fmt.Fprintln(os.Stderr, "The link works once, within 2 minutes.")
}

func dashboardLoginURL(baseURL, token string, issuedAt time.Time) string {
	issuedAtUnix := issuedAt.Unix()
	query := url.Values{
		"ts":  {strconv.FormatInt(issuedAtUnix, 10)},
		"sig": {greyproxy.SignDashboardLogin(token, issuedAtUnix)},
	}
	return baseURL + "/auth?" + query.Encode()
}

// addLocalAPIToken sends the API token when the token file exists, so CLI
// commands keep working once requireApiToken is on.
func addLocalAPIToken(req *http.Request) {
	token, err := greyproxy.ReadAPIToken(greyproxyDataHome())
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
}
