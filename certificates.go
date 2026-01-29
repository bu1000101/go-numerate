package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	parser "github.com/huner2/go-sddlparse/v2"
)

type template struct {
	name             string
	authority        string
	enabled          bool
	clientAuth       bool
	anyPurpose       bool
	enrolleeSupplies bool
	certNameFlag     []string
	managerApproval  bool
	enrollmentRights []string
	objectControl    []string
	eku              []string
	dangerousEnroll  bool
	dangerousWrite   bool
}

const (
	ENROLLEE_SUPPLIES_SUBJECT      int32 = 0x00000001
	SUBJECT_REQUIRE_DIRECTORY_PATH int32 = 0x00000080

	SUBJECT_ALT_REQUIRE_UPN   int32 = 0x02000000
	SUBJECT_ALT_REQUIRE_DNS   int32 = 0x04000000
	SUBJECT_ALT_REQUIRE_EMAIL int32 = 0x08000000
	SUBJECT_ALT_REQUIRE_GUID  int32 = 0x10000000
)

func CertificateNameFlagsFromString(s string) ([]string, error) {
	// Parse LDAP string to int32 (signed!)
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return nil, err
	}

	flags := int32(v)

	flagMap := []struct {
		Bit  int32
		Name string
	}{
		{0x00000001, "EnrolleeSuppliesSubject"},
		{0x00000080, "SubjectRequireDirectoryPath"},
		{0x02000000, "SubjectAltRequiresUPN"},
		{0x04000000, "SubjectAltRequiresDNS"},
		{0x08000000, "SubjectAltRequiresEMAIL"},
		{0x10000000, "SubjectAltRequiresGUID"},
	}

	var result []string
	for _, f := range flagMap {
		if flags&f.Bit != 0 {
			result = append(result, f.Name)
		}
	}

	return result, nil
}

var certTemplates []template

func certSearch(cert string) *ldap.SearchRequest {
	// Search for the given username
	//baseDN := "DC=bui,DC=home"
	var filter string
	var certDN string
	if cert != "*" {
		certDN = "CN=Public Key Services,CN=Services,CN=Configuration," + baseDN
		//baseDN = "CN=Certification Authorities,CN=Public Key Services,CN=Services," + baseDN
		filter = fmt.Sprintf("(&(objectClass=pKICertificateTemplate)(cn=%s))", cert)
		//filter = fmt.Sprintf("(&(objectClass=certificationAuthority)(cn=%s))", cert)
	} else {
		fmt.Println("test")
		//baseDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + baseDN
		certDN = "CN=Public Key Services,CN=Services,CN=Configuration," + baseDN
		filter = "(&(objectClass=pKICertificateTemplate))"
		//filter = "(&(objectClass=certificationAuthority))"
		//filter = "(&(objectClass=pKIEnrollmentService)(certificateTemplates=*))"
	}
	// Filters must start and finish with ()!
	return ldap.NewSearchRequest(certDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{}, []ldap.Control{})

}

func EKUOIDToString(oid string) string {
	switch oid {
	case "1.3.6.1.4.1.311.20.2.1":
		return "Certificate Request Agent"

	// Common EKUs
	case "1.3.6.1.5.5.7.3.1":
		return "Server Authentication"
	case "1.3.6.1.5.5.7.3.2":
		return "Client Authentication"
	case "1.3.6.1.5.5.7.3.3":
		return "Code Signing"
	case "1.3.6.1.5.5.7.3.4":
		return "Email Protection"
	case "1.3.6.1.5.5.7.3.8":
		return "Time Stamping"
	case "1.3.6.1.5.5.7.3.9":
		return "OCSP Signing"
	case "1.3.6.1.5.2.3.5":
		return "Kerberos Client Authentication"

	// Microsoft-specific EKUs
	case "1.3.6.1.4.1.311.10.3.4":
		return "Encrypting File System (EFS)"
	case "1.3.6.1.4.1.311.20.2.2":
		return "Smart Card Logon"

	default:
		return oid
	}
}

const (
	// LDAP_SERVER_SD_FLAGS_OID control
	ControlTypeSDFlags = "1.2.840.113556.1.4.801"
)

func GetCertificateTemplateSD(l *ldap.Conn, templateCN string) ([]byte, error) {

	// Build DN
	dn := fmt.Sprintf(
		"CN=%s,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,",
		templateCN,
	)
	dn += baseDN

	// BER encoding for an ASN.1 SEQUENCE containing an INTEGER with value 7
	// 0x30 (Sequence) 0x03 (Length) 0x02 (Integer) 0x01 (Length) 0x07 (Value)
	controlValue := string([]byte{0x30, 0x03, 0x02, 0x01, 0x07})

	// Create the control
	control := ldap.NewControlString(ControlTypeSDFlags, true, controlValue)

	searchReq := ldap.NewSearchRequest(
		dn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"nTSecurityDescriptor"},
		[]ldap.Control{control},
	)

	sr, err := l.Search(searchReq)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) != 1 {
		return nil, fmt.Errorf("expected 1 entry, got %d", len(sr.Entries))
	}
	sd := sr.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if sd == nil {
		return nil, fmt.Errorf("nTSecurityDescriptor not returned")
	}
	return sd, nil

}

var sidRegex = regexp.MustCompile(`^S-\d+(-\d+)+$`)

func extractUser(ace string) (string, error) {
	ace = strings.TrimSpace(ace)
	ace = strings.TrimPrefix(ace, "(")
	ace = strings.TrimSuffix(ace, ")")
	parts := strings.Split(ace, ";")
	if len(parts) < 6 {
		return "", fmt.Errorf("invalid ACE format, got %d fields", len(parts))
	}
	sid := parts[5]
	if sid == "" {
		return "", fmt.Errorf("SID field is empty")
	} else if sid == "DA" {
		return "Domain Admins", nil
	} else if sid == "EA" {
		return "Enterprise Admins", nil
	}
	return sid, nil

}

func SIDStringToBytes(sid string) ([]byte, error) {
	parts := strings.Split(sid, "-")
	if len(parts) < 4 || parts[0] != "S" {
		return nil, fmt.Errorf("invalid SID")
	}

	revision, _ := strconv.Atoi(parts[1])
	authority, _ := strconv.ParseUint(parts[2], 10, 48)

	subAuthCount := len(parts) - 3

	buf := make([]byte, 8+4*subAuthCount)
	buf[0] = byte(revision)
	buf[1] = byte(subAuthCount)

	// Identifier Authority (big-endian 6 bytes)
	for i := 0; i < 6; i++ {
		buf[2+i] = byte(authority >> uint(8*(5-i)))
	}

	// SubAuthorities (little-endian uint32)
	offset := 8
	for _, sa := range parts[3:] {
		val, _ := strconv.ParseUint(sa, 10, 32)
		binary.LittleEndian.PutUint32(buf[offset:], uint32(val))
		offset += 4
	}

	return buf, nil
}

func escapeLDAPBinary(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		sb.WriteString(fmt.Sprintf("\\%02x", c))
	}
	return sb.String()
}

func ResolveSIDLDAP(l *ldap.Conn, baseDN, sid string) (string, error) {
	sidBytes, err := SIDStringToBytes(sid)
	if err != nil {
		return "", err
	}

	filter := fmt.Sprintf("(objectSid=%s)", escapeLDAPBinary(sidBytes))

	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		filter,
		[]string{"sAMAccountName", "cn"},
		nil,
	)

	res, err := l.Search(req)
	if err != nil {
		return "", err
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("SID not found")
	}

	if name := res.Entries[0].GetAttributeValue("sAMAccountName"); name != "" {
		return name, nil
	}
	if res.Entries[0].GetAttributeValue("cn") == "S-1-5-11" {
		return "Authenticated Users", nil
	}
	if res.Entries[0].GetAttributeValue("cn") == "S-1-5-9" {
		return "Enterprise Domain Controllers", nil
	}
	return res.Entries[0].GetAttributeValue("cn"), nil
}

// Access mask for enrolling
const (
	ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100

	WRITE_DAC   = 0x00040000
	WRITE_OWNER = 0x00080000
	GENERIC_ALL = 0x10000000
)

const (
	ACCESS_ALLOWED_ACE_TYPE        = 0x00
	ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
)

func HasControlAccess(a parser.ACE) bool {
	return a.AccessMask&ADS_RIGHT_DS_CONTROL_ACCESS != 0
}

func CanEnroll(a parser.ACE) bool {
	if a.Type != ACCESS_ALLOWED_OBJECT_ACE_TYPE {
		return false
	}

	return HasControlAccess(a)
}

func CanWriteDACL(a parser.ACE) bool {
	return a.AccessMask&WRITE_DAC != 0
}

func CanWriteOwner(a parser.ACE) bool {
	return a.AccessMask&WRITE_OWNER != 0
}

func IsFullControl(a parser.ACE) bool {

	if a.AccessMask&GENERIC_ALL != 0 {
		return true
	}

	if a.AccessMask&0x000F01FF == 0x000F01FF {
		return true
	}

	return false
}

func CanModifyTemplate(a parser.ACE) bool {
	return IsFullControl(a) ||
		CanWriteDACL(a) ||
		CanWriteOwner(a)
}

const CT_FLAG_PEND_ALL_REQUESTS = 0x2

func RequiresManagerApproval(flagStr string) (bool, error) {
	val, err := strconv.Atoi(flagStr)
	if err != nil {
		return false, err
	}

	return (val & CT_FLAG_PEND_ALL_REQUESTS) != 0, nil
}

type EnterpriseCA struct {
	Name      string
	DNSName   string
	Templates []string
	DN        string
}

func GetEnterpriseCAs(l *ldap.Conn, baseDN string) ([]EnterpriseCA, error) {

	configNC := "CN=CDP,CN=Public Key Services,CN=Services," + baseDN
	fmt.Println("CONFIG: ", configNC)
	req := ldap.NewSearchRequest(
		configNC,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=pKIEnrollmentService)",
		[]string{
			"cn",
			"dNSHostName",
			"certificateTemplates",
			"distinguishedName",
		},
		nil,
	)

	res, err := l.Search(req)
	if err != nil {
		fmt.Println("nothing")
		return nil, err
	}

	var cas []EnterpriseCA

	for _, e := range res.Entries {
		fmt.Println(len(res.Entries))
		ca := EnterpriseCA{
			Name:      e.GetAttributeValue("cn"),
			DNSName:   e.GetAttributeValue("dNSHostName"),
			Templates: e.GetAttributeValues("certificateTemplates"),
			DN:        e.DN,
		}

		cas = append(cas, ca)
	}

	return cas, nil
}
func PrintCAs(cas []EnterpriseCA) {
	for _, ca := range cas {

		fmt.Println("==== CA ====")
		fmt.Println("Name:", ca.Name)
		fmt.Println("DNS :", ca.DNSName)
		fmt.Println("DN  :", ca.DN)

		fmt.Println("Templates:")
		for _, t := range ca.Templates {
			fmt.Println("  -", t)
		}

		fmt.Println()
	}
}

func certConfirmed(l *ldap.Conn, query string, output string) {

	cas, err := GetEnterpriseCAs(l, baseDN)
	if err == nil {
		PrintCAs(cas)
	}
	searchReq := certSearch(query)
	result, err := l.Search(searchReq)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("")
	log.Println("Got", len(result.Entries), "search results")

	switch output {
	case "console":
		for _, entry := range result.Entries {
			var t template
			t.enabled = true
			for _, attribute := range entry.Attributes {
				if attribute.Name == "pKIExtendedKeyUsage" {
					for i := 0; i < len(attribute.Values); i++ {
						attribute.Values[i] = EKUOIDToString(attribute.Values[i])
						t.eku = append(t.eku, attribute.Values[i])
					}

				}
				if attribute.Name == "msPKI-Enrollment-Flag" {
					manager, err := RequiresManagerApproval(attribute.Values[0])
					if err == nil {
						t.managerApproval = manager
					}
				}
				if attribute.Name == "cn" {
					t.name = attribute.Values[0]
					sdBytes, err := GetCertificateTemplateSD(l, attribute.Values[0])
					if err != nil {
						log.Fatal(err)
					}
					//fmt.Printf("Got security descriptor: %d bytes\n", len(sdBytes))
					sddl, err := parser.SDDLFromBinary([]byte(sdBytes))
					for n := 0; n < len(sddl.DACL); n++ {
						if CanEnroll(*sddl.DACL[n]) {
							sidEnroll, err := ResolveSIDLDAP(l, baseDN, sddl.DACL[n].SID)
							if err == nil {
								t.enrollmentRights = append(t.enrollmentRights, sidEnroll)
								if sidEnroll == "Authenticated Users" || sidEnroll == "Domain Users" || sidEnroll == "Domain Computers" {
									t.dangerousEnroll = true
								}
							}

						}
						if CanModifyTemplate(*sddl.DACL[n]) {
							sidWrite, err := ResolveSIDLDAP(l, baseDN, sddl.DACL[n].SID)
							if err == nil {
								t.objectControl = append(t.objectControl, sidWrite)
								if sidWrite == "Authenticated Users" || sidWrite == "Domain Users" || sidWrite == "Domain Computers" {
									t.dangerousWrite = true
								}
							}

						}

					}

				}
				if attribute.Name == "msPKI-Certificate-Name-Flag" {
					t.certNameFlag, err = CertificateNameFlagsFromString(attribute.Values[0])
					if err != nil {
						return
					}

				}
				//fmt.Printf("  %s: %v\n", attribute.Name, noBrackets(attribute.Values))
			}
			certTemplates = append(certTemplates, t)
			fmt.Printf("\n\n")
		}

		for i := 0; i < len(certTemplates); i++ {
			fmt.Println("===============================================================")
			fmt.Printf("Certificate #%d: \n", i+1)
			fmt.Printf("Template Name				: %s\n", certTemplates[i].name)
			fmt.Printf("Enabled					: %t\n", certTemplates[i].enabled)
			fmt.Printf("Certificate Authority			: %s\n", certTemplates[i].authority)

			for j := 0; j < len(certTemplates[i].eku); j++ {
				if j == 0 {
					fmt.Printf("Extended Key Usage			: %s\n", certTemplates[i].eku[j])
				} else {
					fmt.Printf("					: %s\n", certTemplates[i].eku[j])
				}
				if certTemplates[i].eku[j] == "Client Authentication" {
					certTemplates[i].clientAuth = true
				}
			}
			for j := 0; j < len(certTemplates[i].certNameFlag); j++ {
				if j == 0 {
					fmt.Printf("Certificate Name Flag			: %s\n", certTemplates[i].certNameFlag[j])
				} else {
					fmt.Printf("					: %s\n", certTemplates[i].certNameFlag[j])
				}
				if certTemplates[i].certNameFlag[j] == "EnrolleeSuppliesSubject" {
					certTemplates[i].enrolleeSupplies = true
				}
			}
			fmt.Printf("Client Authentication			: %t\n", certTemplates[i].clientAuth)
			fmt.Printf("Enrollee Supplies Subject		: %t\n", certTemplates[i].enrolleeSupplies)
			fmt.Printf("Requires Manager Approval		: %t\n", certTemplates[i].managerApproval)

			fmt.Printf("Any Purpose				: %t\n", certTemplates[i].anyPurpose)
			fmt.Println("---------------------")
			for j := 0; j < len(certTemplates[i].enrollmentRights); j++ {
				if j == 0 {
					fmt.Printf("Enrollment Rights			: %s\n", certTemplates[i].enrollmentRights[j])
				} else {
					fmt.Printf("					  %s\n", certTemplates[i].enrollmentRights[j])
				}
			}
			fmt.Println("---------------------")
			for j := 0; j < len(certTemplates[i].objectControl); j++ {
				if j == 0 {
					fmt.Printf("Write Permissions			: %s\n", certTemplates[i].objectControl[j])
				} else {
					fmt.Printf("					  %s\n", certTemplates[i].objectControl[j])
				}
			}
			if certTemplates[i].dangerousEnroll && !certTemplates[i].managerApproval && certTemplates[i].enrolleeSupplies && certTemplates[i].clientAuth {
				fmt.Printf("\n[*] ESC1 : Low level user can supplie enrollee subject!")
			}
			if certTemplates[i].dangerousWrite {
				fmt.Printf("\n[*] ESC5 : Low level user can change certificate template!")
			}

		}
	}
}
