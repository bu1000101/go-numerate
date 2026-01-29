package main

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var timeAttrs = map[string]bool{
	"pwdLastSet":         true,
	"accountExpires":     true,
	"lastLogonTimestamp": true,
}

// USER ACCOUNT CONTROL FLAGS TO CHECK
var uacFlags = map[int]string{
	0x0001:    "SCRIPT",
	0x0002:    "ACCOUNTDISABLE",
	0x0008:    "HOMEDIR_REQUIRED",
	0x0010:    "LOCKOUT",
	0x0020:    "PASSWD_NOTREQD",
	0x0040:    "PASSWD_CANT_CHANGE",
	0x0080:    "ENCRYPTED_TEXT_PASSWORD_ALLOWED",
	0x0100:    "TEMP_DUPLICATE_ACCOUNT",
	0x0200:    "NORMAL_ACCOUNT",
	0x10000:   "DONT_EXPIRE_PASSWORD",
	0x20000:   "MNS_LOGON_ACCOUNT",
	0x40000:   "SMARTCARD_REQUIRED",
	0x80000:   "TRUSTED_FOR_DELEGATION",
	0x100000:  "NOT_DELEGATED",
	0x200000:  "USE_DES_KEY_ONLY",
	0x400000:  "DONT_REQUIRE_PREAUTH",
	0x800000:  "PASSWORD_EXPIRED",
	0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}

// CREATING THE USER SEARCH FUNCTIONALITY
func userSearch(user string) *ldap.SearchRequest {
	// Search for the given username
	//baseDN := "DC=bui,DC=home"
	var filter string
	if user != "*" {
		filter = fmt.Sprintf("(&(objectClass=user)(sAMAccountType=805306368)(CN=%s))", user)
	} else {
		fmt.Println("test")
		filter = "(&(objectClass=user)(sAMAccountType=805306368))"
	}
	// Filters must start and finish with ()!
	return ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{"cn",
		"sAMAccountName",
		"userPrincipalName",
		"distinguishedName",
		"memberOf",
		"whenCreated",
		"whenChanged",
		"lastLogonTimestamp",
		"pwdLastSet",
		"accountExpires",
		"userAccountControl",
		"objectsid",
		"Description",
		"Title",
		"Department",
		"Company",
		"Email"}, []ldap.Control{})

}

// changing format of pwdLastSet, lastLogonTimestamp
func adFileTimeToTime(v string) string {
	if v == "" || v == "0" || v == "9223372036854775807" {
		return "NEVER"
	}

	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return ""
	}

	// Convert Windows FILETIME → Unix time
	unix := (i / 10000000) - 11644473600
	t := time.Unix(unix, 0).UTC()
	return t.Format("2006-01-02 15:04")
}

// CHANGING THE WHENCREATED WHENCHANGED TIME
func parseGeneralizedTimeString(v string) string {
	if v == "" {
		return ""
	}

	var t time.Time
	var err error

	// Try with fractional seconds
	if strings.Contains(v, ".") {
		t, err = time.Parse("20060102150405.0Z", v)
		if err != nil {
			return ""
		}
	} else {
		// Without fractional seconds
		t, err = time.Parse("20060102150405Z", v)
		if err != nil {
			return ""
		}
	}

	// Format as YYYY-MM-DD HH:MM
	return t.Format("2006-01-02 15:04")
}

// PARSE UAC to show if enabled also what flags
func parseUserAccountControl(uacStr string) string {
	if uacStr == "" {
		return "Unknown"
	}

	uac, err := strconv.Atoi(uacStr)
	if err != nil {
		return "Invalid"
	}

	// Determine enabled/disabled status
	status := "Enabled"
	if uac&0x0002 != 0 { // ACCOUNTDISABLE bit
		status = "Disabled"
	}

	// Collect all set flags
	setFlags := []string{}
	for bit, name := range uacFlags {
		if uac&bit != 0 {
			setFlags = append(setFlags, name)
		}
	}

	if len(setFlags) == 0 {
		return status
	}

	// Return as "Status (FLAG1, FLAG2, ...)"
	return fmt.Sprintf("%s (%s)", status, strings.Join(setFlags, ", "))
}

// MAKES SID BYTES TO STRING FOR SEARCH
func sidToString(b []byte) string {
	if len(b) < 8 {
		return ""
	}

	revision := b[0]
	subCount := int(b[1])
	identifierAuthority := uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 |
		uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])

	sid := fmt.Sprintf("S-%d-%d", revision, identifierAuthority)

	offset := 8
	for i := 0; i < subCount; i++ {
		if offset+4 > len(b) {
			break
		}
		sub := binary.LittleEndian.Uint32(b[offset:])
		sid += fmt.Sprintf("-%d", sub)
		offset += 4
	}
	return sid
}

// jsut removes brackets lol
func noBrackets(values []string) string {
	if len(values) == 0 {
		return ""
	}
	if len(values) == 1 {
		return values[0]
	}
	return strings.Join(values, " ")
}

var rowToAdd [16]string

func csvExport(data [][]string, filename string) error {
	file, err := os.Create(filename + ".csv")
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, value := range data {
		if err := writer.Write(value); err != nil {
			return err // let's return errors if necessary, rather than having a one-size-fits-all error handler
		}
	}
	return nil
}

func userConfirmed(l *ldap.Conn, query string, output string) {
	searchReq := userSearch(query)

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
				if timeAttrs[attribute.Name] {
					attribute.Values[0] = adFileTimeToTime(attribute.Values[0])

				} else if attribute.Name == "whenCreated" || attribute.Name == "whenChanged" {
					attribute.Values[0] = parseGeneralizedTimeString(attribute.Values[0])
				} else if attribute.Name == "objectSid" {
					attribute.Values[0] = sidToString(entry.GetRawAttributeValue("objectSid"))
				} else if attribute.Name == "userAccountControl" {
					attribute.Values[0] = parseUserAccountControl(attribute.Values[0])
				} else if attribute.Name == "memberOf" {
					if len(attribute.Values) > 1 {
						attribute.Values[0] = attribute.Values[0] + "\n"
						for i := 1; i < len(attribute.Values)-1; i++ {
							attribute.Values[i] = "           " + attribute.Values[i] + "\n"
						}
						attribute.Values[len(attribute.Values)-1] = "           " + attribute.Values[len(attribute.Values)-1]
					}
				} else if attribute.Name == "cn" {
					attribute.Name = "USER"
				}

				fmt.Printf("  %s: %v\n", attribute.Name, noBrackets(attribute.Values))
			}
			fmt.Printf("\n\n")
		}
	case "csv":
		csvOutput := [][]string{
			{"cn",
				"sAMAccountName",
				"userPrincipalName",
				"distinguishedName",
				"userAccountControl",
				"memberOf",
				"whenCreated",
				"whenChanged",
				"lastLogonTimestamp",
				"pwdLastSet",
				"accountExpires",
				"objectSid",
				"description",
				"title",
				"department",
				"company",
				"email"},
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
			fileName = t.Format("01-02-06-150405") + "-users"
			csvExport(csvOutput, fileName)
		} else {
			csvExport(csvOutput, fileName)
		}
		fmt.Printf("Successfully exported to %s.csv", fileName)
	}
}
