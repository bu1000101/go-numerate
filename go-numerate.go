package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

type gssapiClient struct {
	client  *client.Client
	spn     string
	ctx     *spnego.SPNEGO
	ekey    types.EncryptionKey
	subkey  types.EncryptionKey
	started bool
}

func (g *gssapiClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return g.InitSecContextWithOptions(target, token, nil)
}

func (g *gssapiClient) InitSecContextWithOptions(target string, token []byte, options []int) ([]byte, bool, error) {
	fmt.Printf("[DEBUG] InitSecContext: token=%d bytes, started=%v\n", len(token), g.started)

	if g.ctx == nil {
		fmt.Println("[DEBUG] Creating SPNEGO context")
		g.ctx = spnego.SPNEGOClient(g.client, g.spn)
		_, ekey, err := g.client.GetServiceTicket(g.spn)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get service ticket: %v", err)
		}
		g.ekey = ekey
	}

	if !g.started {
		g.started = true
		fmt.Println("[DEBUG] Generating initial token")
		tok, err := g.ctx.InitSecContext()
		if err != nil {
			return nil, false, err
		}
		tokenBytes, err := tok.Marshal()
		if err != nil {
			return nil, false, err
		}
		fmt.Printf("[DEBUG] Returning %d bytes, needContinue=true\n", len(tokenBytes))
		return tokenBytes, true, nil
	}

	if token != nil && len(token) > 0 {
		fmt.Printf("[DEBUG] Processing server response (%d bytes)\n", len(token))
		var respToken spnego.SPNEGOToken
		if err := respToken.Unmarshal(token); err != nil {
			fmt.Println("[DEBUG] Failed to unmarshal:", err)
			return nil, false, err
		}

		if respToken.NegTokenResp.ResponseToken != nil {
			fmt.Printf("[DEBUG] ResponseToken present (%d bytes)\n", len(respToken.NegTokenResp.ResponseToken))
			var krb5Token spnego.KRB5Token
			if err := krb5Token.Unmarshal(respToken.NegTokenResp.ResponseToken); err == nil {
				if krb5Token.IsAPRep() {
					fmt.Println("[DEBUG] Got AP-REP, extracting subkey")
					encpart, err := crypto.DecryptEncPart(krb5Token.APRep.EncPart, g.ekey, keyusage.AP_REP_ENCPART)
					if err == nil {
						part := &messages.EncAPRepPart{}
						if err = part.Unmarshal(encpart); err == nil {
							g.subkey = part.Subkey
							fmt.Println("[DEBUG] Subkey extracted successfully")
						}
					}
				}
			}
		}
		fmt.Println("[DEBUG] Returning needContinue=false")
		return []byte{}, false, nil
	}

	fmt.Println("[DEBUG] No token, returning needContinue=false")
	return []byte{}, false, nil
}

func (g *gssapiClient) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	fmt.Printf("[DEBUG] NegotiateSaslAuth called with %d bytes\n", len(input))
	token := &gssapi.WrapToken{}
	err := unmarshalWrapToken(token, input, true)
	if err != nil {
		return nil, err
	}

	if (token.Flags & 0b1) == 0 {
		return nil, fmt.Errorf("got a Wrapped token that's not from the server")
	}

	// Use subkey if available and flag is set, otherwise use ekey
	key := g.ekey
	if (token.Flags&0b100) != 0 && g.subkey.KeyType != 0 {
		key = g.subkey
	}

	_, err = token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, err
	}

	pl := token.Payload
	if len(pl) != 4 {
		return nil, fmt.Errorf("server sent bad final token for SASL GSSAPI handshake")
	}

	// Request no security layer
	b := [4]byte{0, 0, 0, 0}
	payload := append(b[:], []byte(authzid)...)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	respToken := &gssapi.WrapToken{
		Flags:     0b100,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 1,
		Payload:   payload,
	}

	if err := respToken.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	return respToken.Marshal()
}

func (g *gssapiClient) DeleteSecContext() error {
	return nil
}

func unmarshalWrapToken(wt *gssapi.WrapToken, b []byte, expectFromAcceptor bool) error {
	if len(b) < 16 {
		return errors.New("bytes shorter than header length")
	}
	tokenID := []byte{0x05, 0x04}
	if !bytes.Equal(tokenID, b[0:2]) {
		return fmt.Errorf("wrong Token ID")
	}
	flags := b[2]
	isFromAcceptor := flags&0x01 == 1
	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag")
	}
	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag not set")
	}
	if b[3] != 0xFF {
		return fmt.Errorf("unexpected filler byte")
	}
	checksumL := binary.BigEndian.Uint16(b[4:6])
	if int(checksumL) > len(b)-16 {
		return fmt.Errorf("inconsistent checksum length")
	}
	payloadStart := 16 + checksumL

	wt.Flags = flags
	wt.EC = checksumL
	wt.RRC = binary.BigEndian.Uint16(b[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(b[8:16])
	wt.CheckSum = b[16:payloadStart]
	wt.Payload = b[payloadStart:]

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

	realm := strings.ToUpper(domainName)

	krb5Conf := config.New()
	krb5Conf.LibDefaults.DefaultRealm = realm
	krb5Conf.LibDefaults.DNSLookupKDC = true
	krb5Conf.LibDefaults.DNSLookupRealm = true
	krb5Conf.LibDefaults.UDPPreferenceLimit = 1

	var krb5Client *client.Client

	if noPass {
		ccachePath := os.Getenv("KRB5CCNAME")
		ccachePath = strings.TrimPrefix(ccachePath, "FILE:")
		fmt.Println("Using ccache:", ccachePath)

		ccache, err := credentials.LoadCCache(ccachePath)
		if err != nil {
			log.Fatal("Failed to load ccache: ", err)
		}

		krb5Client, err = client.NewFromCCache(ccache, krb5Conf)
		if err != nil {
			log.Fatal("Failed to create Kerberos client from ccache: ", err)
		}
	} else {
		krb5Client = client.NewWithPassword(userPtr, realm, pwPtr, krb5Conf)
		err = krb5Client.Login()
		if err != nil {
			log.Fatal("Kerberos login failed: ", err)
		}
	}

	spn := "ldap/" + dcHost
	gssClient := &gssapiClient{client: krb5Client, spn: spn}
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
