package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("domain,hasMX,hasSPF,sprRecord, hasDMARC,dmarcRecord\n")
	var email string
	var dStatus bool
	for scanner.Scan() {
		email = scanner.Text()
		domain := getDomain(email)
		dStatus = checkDomain(domain)
		break
	}
	if err := scanner.Err(); err != nil {
		log.Fatal("Error: could not read from input: %v\n", err)
	}
	if dStatus {
		if isValidEmail(email) {
			fmt.Println("Email is valid")
			if isEmailUsed(email) {
				fmt.Println("Email is being actively used")
			} else {
				fmt.Println("Email is not being actively used")
			}
		} else {
			fmt.Println("Email is not valid")
		}
	}
}

func isValidEmail(email string) bool {
	// Regular expression to validate email address
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	valid, err := regexp.MatchString(emailRegex, email)
	if err != nil {
		return false
	}
	return valid
}

func isEmailUsed(email string) bool {
	// ZeroBounce API endpoint for email verification
	// See https://www.zerobounce.net/docs/email-validation-api-quickstart/ for more info
	url := "add-your-https://api.zerobounce.net/v2/validate"
	apiEndpoint := url

	// ZeroBounce API key (replace with your own key)
	// See https://www.zerobounce.net/docs/email-validation-api-quickstart/ for more info
	key := "add-your-api-key-here"
	apiKey := key

	// Create HTTP client
	client := http.DefaultClient

	// Make API request
	resp, err := client.Get(fmt.Sprintf("%s?apikey=%s&email=%s", apiEndpoint, apiKey, email))
	if err != nil {
		// Handle error
		return false
	}
	defer resp.Body.Close()

	// Parse API response
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		// Handle error
		return false
	}

	// Check if email is valid and deliverable
	if result["status"] == "valid" && result["deliverable"] == true {
		return true
	} else {
		return false
	}
}

// getDomain returns the domain part of an email address
func getDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 1 {
		return parts[1]
	} else {
		return ""
	}
}

// checkDomain checks if a domain has MX, SPF, and DMARC records
func checkDomain(domain string) bool {

	var hasMX, hasSPF, hasDMARC bool
	var spfRecord, dmarcRecord string

	// Check for MX record
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		log.Printf("Error: could not find MX record for %s: %v\n", domain, err)
		return false
	}
	if len(mxRecords) > 0 {
		hasMX = true
	}
	// Check for SPF record
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		log.Printf("Error: could not find TXT record for %s: %v\n", domain, err)
		return false
	}
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			hasSPF = true
			spfRecord = record
			break
		}
	}
	// Check for DMARC record
	dmarcRecords, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		log.Printf("Error: could not find DMARC record for %s: %v\n", domain, err)
		return false
	}
	for _, record := range dmarcRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			hasDMARC = true
			dmarcRecord = record
			break
		}
	}

	fmt.Printf("%v,%v,%v,%v,%v,%v\n", domain, hasMX, hasSPF, spfRecord, hasDMARC, dmarcRecord)
	return true

}
