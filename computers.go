package main

import (
	"fmt"
	"log"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func compSearch(computer string) *ldap.SearchRequest {
	// Search for the given username
	//baseDN := "DC=bui,DC=home"
	var filter string
	if computer != "*" {
		filter = fmt.Sprintf("(&(objectClass=computer)(sAMAccountType=805306369)(CN=%s))", computer)
	} else {
		fmt.Println("test")
		filter = "(&(objectClass=computer)(sAMAccountType=805306369))"
	}
	// Filters must start and finish with ()!
	return ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{"cn",
		"sAMAccountName",
		"ipv4Address",
		"DNSHostName",
		"distinguishedName",
		"userAccountControl",
		"objectSid",
		"Description",
	}, []ldap.Control{})

}
func computersConfirmed(l *ldap.Conn, query string, output string) {
	searchReq := compSearch(query)

	result, err := l.Search(searchReq)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("")
	log.Println("Got", len(result.Entries), "search results")

	switch output {
	case "console":
		for _, entry := range result.Entries {
			fmt.Println("===============================================================")
			for _, attribute := range entry.Attributes {
				if attribute.Name == "objectSid" {
					attribute.Values[0] = sidToString(entry.GetRawAttributeValue("objectSid"))
				}
				fmt.Printf("  %s: %v\n", attribute.Name, noBrackets(attribute.Values))
			}
			fmt.Printf("\n\n")
		}
	case "csv":
		csvOutput := [][]string{
			{"cn",
				"sAMAccountName",
				"ipv4Address",
				"DNSHostName",
				"distinguishedName",
				"userAccountControl",
				"objectSid",
				"Description"},
		}
		for _, entry := range result.Entries {
			rowToAdd := make([]string, len(csvOutput[0]))
			for i := 0; i < len(csvOutput[0]); i++ {
				for _, attribute := range entry.Attributes {
					if attribute.Name == csvOutput[0][i] {
						if timeAttrs[attribute.Name] {
							attribute.Values[0] = adFileTimeToTime(attribute.Values[0])

						} else if attribute.Name == "whenCreated" || attribute.Name == "whenChanged" {
							attribute.Values[0] = parseGeneralizedTimeString(attribute.Values[0])
						} else if attribute.Name == "objectSid" {
							attribute.Values[0] = sidToString(entry.GetRawAttributeValue("objectSid"))
						} else if attribute.Name == "userAccountControl" {
							attribute.Values[0] = parseUserAccountControl(attribute.Values[0])
						}
						rowToAdd[i] = noBrackets(attribute.Values)
					}
				}
			}
			rowToAddSlice := rowToAdd[:]
			csvOutput = append(csvOutput, rowToAddSlice)
		}
		if fileName == "" {
			t := time.Now()
			fileName = t.Format("01-02-06-150405") + "-computers"
			csvExport(csvOutput, fileName)
		} else {
			csvExport(csvOutput, fileName)
		}
		fmt.Printf("Successfully exported to %s.csv", fileName)

	}
}
