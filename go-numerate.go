package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

type gssapiClient struct {
	client  *client.Client
	spn     string
	ctx     *spnego.SPNEGO
	key     types.EncryptionKey
	started bool
}

func (g *gssapiClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return g.InitSecContextWithOptions(target, token, nil)
}

func (g *gssapiClient) InitSecContextWithOptions(target string, token []byte, options []int) ([]byte, bool, error) {
	fmt.Printf("[DEBUG] InitSecContext called, token len: %d, started: %v\n", len(token), g.started)

	if g.ctx == nil {
		fmt.Println("[DEBUG] Creating SPNEGO client for SPN:", g.spn)
		g.ctx = spnego.SPNEGOClient(g.client, g.spn)
		fmt.Println("[DEBUG] Getting service ticket...")
		_, key, err := g.client.GetServiceTicket(g.spn)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get service ticket: %v", err)
		}
		g.key = key
		fmt.Println("[DEBUG] Got service ticket")
	}

	if !g.started {
		g.started = true
		fmt.Println("[DEBUG] Calling InitSecContext...")
		tok, err := g.ctx.InitSecContext()
		if err != nil {
			return nil, false, err
		}
		fmt.Println("[DEBUG] Marshaling token...")
		tokenBytes, err := tok.Marshal()
		if err != nil {
			return nil, false, err
		}
		fmt.Printf("[DEBUG] Returning token, len: %d, needContinue: true\n", len(tokenBytes))
		return tokenBytes, true, nil
	}

	if token != nil && len(token) > 0 {
		fmt.Printf("[DEBUG] Processing server response token (len=%d)...\n", len(token))
		var respToken spnego.SPNEGOToken
		if err := respToken.Unmarshal(token); err != nil {
			fmt.Println("[DEBUG] Failed to unmarshal response token:", err)
			return nil, false, err
		}
		fmt.Println("[DEBUG] Calling AcceptSecContext...")
		_, _, status := g.ctx.AcceptSecContext(&respToken)
		fmt.Printf("[DEBUG] AcceptSecContext status: %v\n", status.Code)
		if status.Code != gssapi.StatusComplete && status.Code != gssapi.StatusContinueNeeded {
			return nil, false, fmt.Errorf("GSSAPI: %v", status)
		}
		if status.Code == gssapi.StatusContinueNeeded {
			return nil, true, nil
		}
	} else {
		fmt.Printf("[DEBUG] No server token to process (token=%v)\n", token)
	}
	fmt.Println("[DEBUG] InitSecContext complete, returning needContinue=false")
	return []byte{}, false, nil
}

func (g *gssapiClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	fmt.Printf("[DEBUG] NegotiateSaslAuth CALLED! token len: %d, authzid: %s\n", len(token), authzid)
	fmt.Printf("[DEBUG] Token bytes: %x\n", token)

	if len(token) == 0 {
		return nil, fmt.Errorf("empty token")
	}

	var wrapToken gssapi.WrapToken
	if err := wrapToken.Unmarshal(token, true); err != nil {
		fmt.Println("[DEBUG] WrapToken unmarshal error:", err)
		return nil, err
	}

	fmt.Println("[DEBUG] Verifying wrap token...")
	if ok, err := wrapToken.Verify(g.key, gssapi.ContextFlagMutual); !ok || err != nil {
		return nil, fmt.Errorf("token verification failed: %v", err)
	}

	payload := wrapToken.Payload
	if len(payload) < 4 {
		return nil, fmt.Errorf("invalid token length")
	}

	response := make([]byte, 4+len(authzid))
	response[0] = payload[0] & 0x01
	copy(response[1:4], payload[1:4])
	copy(response[4:], []byte(authzid))

	fmt.Println("[DEBUG] Creating response wrap token...")
	respToken, err := gssapi.NewInitiatorWrapToken(response, g.key)
	if err != nil {
		return nil, err
	}

	fmt.Println("[DEBUG] NegotiateSaslAuth complete")
	return respToken.Marshal()
}

func (g *gssapiClient) DeleteSecContext() error {
	return nil
}

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

	var krb5Client *client.Client

	if noPass {
		ccachePath := os.Getenv("KRB5CCNAME")
		ccachePath = strings.TrimPrefix(ccachePath, "FILE:")
		fmt.Println("Using ccache:", ccachePath)

		ccache, err := credentials.LoadCCache(ccachePath)
		if err != nil {
			log.Fatal("Failed to load ccache: ", err)
		}

		krb5Conf := config.New()
		krb5Conf.LibDefaults.DefaultRealm = strings.ToUpper(domainName)
		krb5Conf.LibDefaults.DNSLookupKDC = true

		krb5Client, err = client.NewFromCCache(ccache, krb5Conf)
		if err != nil {
			log.Fatal("Failed to create Kerberos client from ccache: ", err)
		}
	} else {
		krb5Conf := config.New()
		krb5Conf.LibDefaults.DefaultRealm = strings.ToUpper(domainName)
		krb5Conf.LibDefaults.DNSLookupKDC = true

		krb5Client = client.NewWithPassword(userPtr, strings.ToUpper(domainName), pwPtr, krb5Conf)
		err = krb5Client.Login()
		if err != nil {
			log.Fatal("Kerberos login failed: ", err)
		}
	}

	spn := "ldap/" + dcHost
	gssClient := &gssapiClient{
		client: krb5Client,
		spn:    spn,
	}

	fmt.Println("Attempting Kerberos authentication...")
	fmt.Println("[DEBUG] Calling l.GSSAPIBind...")
	err = l.GSSAPIBind(gssClient, spn, "")
	fmt.Println("[DEBUG] GSSAPIBind returned")
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
	l, err := ldap.DialURL(ldapURL)
	if err != nil {
		log.Fatal(err)

	}
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
