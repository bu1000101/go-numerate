package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/go-ldap/ldap/v3"
)

var userPtr string
var pwPtr string
var dcIP string
var domainPtr string
var searchItem string
var l ldap.Conn
var baseDN string
var query string
var outputType string
var fileName string

func init() {

	flag.StringVar(&userPtr, "username", "", "username")
	flag.StringVar(&userPtr, "u", "", "username")
	flag.StringVar(&pwPtr, "password", "", "password")
	flag.StringVar(&pwPtr, "p", "", "password")
	flag.StringVar(&dcIP, "dc-ip", "", "Domain Controller IP")
	flag.StringVar(&domainPtr, "domain", "", "Active Directory Domain")
	flag.StringVar(&domainPtr, "d", "", "Active Directory Domain")
	flag.StringVar(&searchItem, "search", "", "(users, computers, oudated computers, certificates)")
	flag.StringVar(&query, "query", "*", "search query")
	flag.StringVar(&query, "q", "*", "search query")
	flag.StringVar(&outputType, "output", "console", "(console*, csv)")
	flag.StringVar(&outputType, "o", "console", "(console*, csv)")
	flag.StringVar(&fileName, "filename", "", "File Name")
	flag.StringVar(&fileName, "f", "", "File Name")

}

func checkNec() {
	if userPtr == "" {
		fmt.Println("Error: --username or -u is required")
		os.Exit(1)
	}
	if pwPtr == "" {
		fmt.Println("Error: --password or -p is required")
		os.Exit(1)
	}
	if dcIP == "" {
		fmt.Println("Error: --dc-ip is required")
		os.Exit(1)
	}
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
		[]string{"defaultNamingContext"},
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
	//fmt.Println("Base DN:", baseDN)
	//username and pw bind
	err = l.Bind(userPtr, pwPtr)
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("Successfully authenticated!")
		fmt.Println("Base DN: ", baseDN)
	}
}

func main() {
	fmt.Println("                                                        _   _             ")
	fmt.Println("  __ _  ___        _ __  _   _ _ __ ___   ___ _ __ __ _| |_(_) ___  _ __  ")
	fmt.Println(" / _` |/ _ \\ _____| '_ \\| | | | '_ ` _ \\ / _ \\ '__/ _` | __| |/ _ \\| '_ \\ ")
	fmt.Println("| (_| | (_) |_____| | | | |_| | | | | | |  __/ | | (_| | |_| | (_) | | | |")
	fmt.Println(" \\__, |\\___/      |_| |_|\\__,_|_| |_| |_|\\___|_|  \\__,_|\\__|_|\\___/|_| |_|")
	fmt.Println(" |___/                                                                    ")

	//var searchUser string
	//var outputType string
	flag.Parse()
	checkNec()
	ldapURL := "ldap://" + dcIP + ":389"
	l, err := ldap.DialURL(ldapURL)
	if err != nil {
		log.Fatal(err)

	}
	defer l.Close()
	authenticate(l)
	if searchItem == "" {
		fmt.Print("Please select:\n(users, computers, outdated-computers, certificates)\n")
		fmt.Scan(&searchItem)
	}

	//fmt.Println("Output?")
	//fmt.Scan(&outputType)
	switch searchItem {
	case "users":
		userConfirmed(l, query, outputType)
	case "computers":
		computersConfirmed(l, query, outputType)
	case "certs":
		certConfirmed(l, query, outputType)
	}
}
