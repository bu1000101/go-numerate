# go-numerate
Enumerate an Active Directory Environment using LDAP written in GO

Alot of inspiration out of powerview, certipy and impacket into the GO language. Much thanks to the community.

Installation:
```
git clone https://github.com/bu1000101/go-numerate.git
go build -o go-numerate
```

Authentication Supported:
```
1. Password: -u user -p password -dc-ip <IP>
2. NTLM hash: -u user -H hash -dc-ip <IP> (or --hashes LM:NT)
3. Kerberos with password: -u user -p password -k -dc-host <hostname>
4. Kerberos with ccache: -k -no-pass -dc-host <hostname> (reads KRB5CCNAME)
```

Examples:
```bash
# Password authentication
./go-numerate -u username -p password -dc-ip 10.0.0.1

# NTLM hash authentication (pass-the-hash)
./go-numerate -u username -H 32charNThash -dc-ip 10.0.0.1
./go-numerate -u username --hashes aad3b435b51404eeaad3b435b51404ee:NThash -dc-ip 10.0.0.1

# Kerberos with password
./go-numerate -u username -p password -k -dc-host dc01.domain.local -d domain.local

# Kerberos with ccache (no password)
export KRB5CCNAME=/tmp/krb5cc_user
./go-numerate -k -no-pass -dc-host dc01.domain.local -d domain.local

# ccache with FILE: prefix also works
export KRB5CCNAME=FILE:/tmp/krb5cc_user
```

Note: Kerberos authentication (`-k`) requires `-dc-host` (hostname), not `-dc-ip`.

Example search for users:
```
// Search specific user and output to console
go run . -u 'bui-user' -p 'password!' --dc-ip 192.168.1.139 --search users --query 'bui-user'

// Search all users and output to console
go run . -u 'bui-user' -p 'password!' --dc-ip 192.168.1.139 --search users
go run . -u 'bui-user' -p 'password!' --dc-ip 192.168.1.139 --search users --query '*'

// Search all admin users
go run . -u 'bui-user' -p 'password!' --dc-ip 192.168.1.139 --search users --query '*admin*'

// Add output CSV to output to CSV file
--output csv
```
Example search for computers:
```
// Search specific computer and output to console
go run . -u 'bui-user' -p 'password!' --dc-ip 192.168.1.139 --search computers --query 'BUI-WORKSTATION'

// Search all computers and output to console
go run . -u 'bui-user' -p 'password!' --dc-ip 192.168.1.139 --search computers
go run . -u 'bui-user' -p 'password!' --dc-ip 192.168.1.139 --search computers --query '*'

// Add output CSV to output to CSV file
--output csv
```

Example search for certificate templates:
```
// Search specific template and output to console
go run . -u 'bui-user' -p 'password!' --dc-ip 192.168.1.139 --search certs --query 'Users'

// Search all templates and output to console
go run . -u 'bui-user' -p 'password!' --dc-ip 192.168.1.139 --search certs
go run . -u 'bui-user' -p 'password!' --dc-ip 192.168.1.139 --search certs --query '*'

```

Example Output
<img width="1514" height="1160" alt="image" src="https://github.com/user-attachments/assets/54c1273c-8d6b-4b6d-8f3c-f7a571b020db" />
