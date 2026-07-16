package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
)

var userPtr string
var pwPtr string
var hashPtr string
var kerberosAuth bool
var noPass bool
var dcIP string
var dcHost string
var domainPtr string
var searchItem string
var l ldap.Conn
var baseDN string
var query string
var outputType string
var fileName string
var forestDN string

func init() {

	flag.StringVar(&userPtr, "username", "", "username")
	flag.StringVar(&userPtr, "u", "", "username")
	flag.StringVar(&pwPtr, "password", "", "password")
	flag.StringVar(&pwPtr, "p", "", "password")
	flag.StringVar(&hashPtr, "hashes", "", "NT hash for pass-the-hash authentication (LM:NT or just NT)")
	flag.StringVar(&hashPtr, "H", "", "NT hash for pass-the-hash authentication (LM:NT or just NT)")
	flag.BoolVar(&kerberosAuth, "k", false, "Use Kerberos authentication")
	flag.BoolVar(&noPass, "no-pass", false, "No password (use with -k for ccache auth)")
	flag.StringVar(&dcIP, "dc-ip", "", "Domain Controller IP")
	flag.StringVar(&dcHost, "dc-host", "", "Domain Controller hostname (required for -k)")
	flag.StringVar(&domainPtr, "domain", "", "Active Directory Domain")
	flag.StringVar(&domainPtr, "d", "", "Active Directory Domain")
	flag.StringVar(&searchItem, "search", "", "(users, computers, oudated computers, certs(cert templates))")
	flag.StringVar(&query, "query", "*", "search query")
	flag.StringVar(&query, "q", "*", "search query")
	flag.StringVar(&outputType, "output", "console", "(console*, csv)")
	flag.StringVar(&outputType, "o", "console", "(console*, csv)")
	flag.StringVar(&fileName, "filename", "", "File Name")
	flag.StringVar(&fileName, "f", "", "File Name")

}

func checkNec() {
	if kerberosAuth {
		if dcHost == "" {
			fmt.Println("Error: --dc-host is required when using -k")
			os.Exit(1)
		}
		if noPass {
			ccache := os.Getenv("KRB5CCNAME")
			if ccache == "" {
				fmt.Println("Error: KRB5CCNAME environment variable not set")
				os.Exit(1)
			}
		}
	} else {
		if userPtr == "" {
			fmt.Println("Error: --username or -u is required")
			os.Exit(1)
		}
		if pwPtr == "" && hashPtr == "" {
			fmt.Println("Error: --password (-p) or --hashes (-H) is required")
			os.Exit(1)
		}
		if dcIP == "" {
			fmt.Println("Error: --dc-ip is required")
			os.Exit(1)
		}
	}
}

func DNtoDomain(dn string) string {
	parts := strings.Split(string(dn), ",")
	var domainParts []string
	for _, part := range parts {
		if strings.HasPrefix(strings.TrimSpace(part), "DC=") {
			domainParts = append(domainParts, strings.TrimPrefix(strings.TrimSpace(part), "DC="))
		}

	}
	return strings.Join(domainParts, ".")

}

func authenticate(l *ldap.Conn) {

	// anonymous bind to get DN
	err := l.UnauthenticatedBind("")
	if err != nil {
		log.Fatal(err)
	}

	// RootDSE query
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "rootDomainNamingContext"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) == 0 {
		log.Fatal("no RootDSE entries returned")
	}

	baseDN = sr.Entries[0].GetAttributeValue("defaultNamingContext")
	fmt.Println("Base DN:", baseDN)
	forestDN = sr.Entries[0].GetAttributeValue("rootDomainNamingContext")
	fmt.Println("Forest DN:", forestDN)

	//username and pw bind
	domainName := DNtoDomain(baseDN)
	if domainPtr != "" {
		domainName = domainPtr
		parts := strings.Split(domainPtr, ".")
		var dnParts []string
		for _, p := range parts {
			dnParts = append(dnParts, "DC="+p)
		}
		baseDN = strings.Join(dnParts, ",")
	}
	userPtr = userPtr + "@" + domainName
	fmt.Println("Attempting authentication with user:", userPtr)
	err = l.Bind(userPtr, pwPtr)
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("Successfully authenticated!")
	}
}

func authenticateHash(l *ldap.Conn) {
	err := l.UnauthenticatedBind("")
	if err != nil {
		log.Fatal(err)
	}

	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "rootDomainNamingContext"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) == 0 {
		log.Fatal("no RootDSE entries returned")
	}

	baseDN = sr.Entries[0].GetAttributeValue("defaultNamingContext")
	fmt.Println("Base DN:", baseDN)
	forestDN = sr.Entries[0].GetAttributeValue("rootDomainNamingContext")
	fmt.Println("Forest DN:", forestDN)

	domainName := DNtoDomain(baseDN)
	if domainPtr != "" {
		domainName = domainPtr
		parts := strings.Split(domainPtr, ".")
		var dnParts []string
		for _, p := range parts {
			dnParts = append(dnParts, "DC="+p)
		}
		baseDN = strings.Join(dnParts, ",")
	}

	ntHash := hashPtr
	if strings.Contains(hashPtr, ":") {
		parts := strings.Split(hashPtr, ":")
		ntHash = parts[len(parts)-1]
	}

	if _, err := hex.DecodeString(ntHash); err != nil {
		log.Fatal("Invalid NT hash format: ", err)
	}
	if len(ntHash) != 32 {
		log.Fatal("NT hash must be 32 hex characters")
	}

	fmt.Println("Attempting NTLM authentication with hash for user:", userPtr)
	err = l.NTLMBindWithHash(domainName, userPtr, ntHash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully authenticated with hash!")
}

func authenticateKerberos(l *ldap.Conn) {
	err := l.UnauthenticatedBind("")
	if err != nil {
		log.Fatal(err)
	}

	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "rootDomainNamingContext"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) == 0 {
		log.Fatal("no RootDSE entries returned")
	}

	baseDN = sr.Entries[0].GetAttributeValue("defaultNamingContext")
	fmt.Println("Base DN:", baseDN)
	forestDN = sr.Entries[0].GetAttributeValue("rootDomainNamingContext")
	fmt.Println("Forest DN:", forestDN)

	if domainPtr != "" {
		parts := strings.Split(domainPtr, ".")
		var dnParts []string
		for _, p := range parts {
			dnParts = append(dnParts, "DC="+p)
		}
		baseDN = strings.Join(dnParts, ",")
	}

	var gssClient *gssapi.Client

	if noPass {
		ccachePath := os.Getenv("KRB5CCNAME")
		ccachePath = strings.TrimPrefix(ccachePath, "FILE:")
		fmt.Println("Using ccache:", ccachePath)

		gssClient, err = gssapi.NewClientFromCCache(ccachePath, "/etc/krb5.conf")
		if err != nil {
			log.Fatal("Failed to create GSSAPI client from ccache: ", err)
		}
	} else {
		realm := strings.ToUpper(domainPtr)
		if realm == "" {
			realm = strings.ToUpper(DNtoDomain(baseDN))
		}
		gssClient, err = gssapi.NewClientWithPassword(userPtr, realm, pwPtr, "/etc/krb5.conf")
		if err != nil {
			log.Fatal("Failed to create GSSAPI client: ", err)
		}
	}
	defer gssClient.Close()

	spn := "ldap/" + dcHost
	fmt.Println("Attempting Kerberos authentication...")
	err = l.GSSAPIBind(gssClient, spn, "")
	if err != nil {
		log.Fatal("GSSAPI bind failed: ", err)
	}
	fmt.Println("Successfully authenticated with Kerberos!")
}

func main() {
	fmt.Println("                                                        _   _             ")
	fmt.Println("  __ _  ___        _ __  _   _ _ __ ___   ___ _ __ __ _| |_(_) ___  _ __  ")
	fmt.Println(" / _` |/ _ \\ _____| '_ \\| | | | '_ ` _ \\ / _ \\ '__/ _` | __| |/ _ \\| '_ \\ ")
	fmt.Println("| (_| | (_) |_____| | | | |_| | | | | | |  __/ | | (_| | |_| | (_) | | | |")
	fmt.Println(" \\__, |\\___/      |_| |_|\\__,_|_| |_| |_|\\___|_|  \\__,_|\\__|_|\\___/|_| |_|")
	fmt.Println(" |___/                                                                    ")

	flag.Parse()
	checkNec()

	var ldapURL string
	if kerberosAuth {
		ldapURL = "ldap://" + dcHost + ":389"
	} else {
		ldapURL = "ldap://" + dcIP + ":389"
	}
	l, err := ldap.DialURL(ldapURL, ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
	if err != nil {
		log.Fatal(err)
	}
	l.SetTimeout(10 * time.Second)
	defer l.Close()

	if kerberosAuth {
		authenticateKerberos(l)
	} else if hashPtr != "" {
		authenticateHash(l)
	} else {
		authenticate(l)
	}
	if searchItem == "" {
		fmt.Print("Please select:\n(users, computers, outdated-computers, certificates)\n")
		fmt.Scan(&searchItem)
	}

	switch searchItem {
	case "users":
		userConfirmed(l, query, outputType)
	case "computers":
		computersConfirmed(l, query, outputType)
	case "certs":
		certConfirmed(l, query, outputType)
	}
}
