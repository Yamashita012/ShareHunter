package detection

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
)

type Config struct {
	Keywords   map[string]string
	Extensions map[string]bool
	Assignment *regexp.Regexp
	PrivateKey *regexp.Regexp
	EntropyMin float64
}

func DefaultConfig() Config {
	k := map[string]string{}
	groups := map[string][]string{"password": {"password", "passwords", "passwd", "pass", "pwd", "passphrase", "userpassword", "adminpassword", "defaultpassword", "dbpassword", "sqlpassword", "servicepassword"}, "authentication": {"auth", "authentication", "credential", "credentials", "login", "logon", "secret", "clientsecret", "client_secret", "apikey", "api_key", "accesskey", "access_key", "secretkey", "secret_key", "token", "bearer", "authorization"}, "account": {"username", "user", "administrator", "admin", "root", "account", "serviceaccount", "service_account", "domainuser"}, "infrastructure": {"connectionstring", "connection_string", "database_url", "db_connection", "ldap_bind", "ftp_password", "smtp_password", "ssh_key", "private_key", "aws_secret_access_key", "azure_client_secret"}}
	for cat, words := range groups {
		for _, w := range words {
			k[w] = cat
		}
	}
	ext := map[string]bool{}
	for _, x := range strings.Fields("txt xml json yaml yml ini conf env config cfg log csv sql ps1 bat cmd sh py php js ts java go") {
		ext[x] = true
	}
	return Config{Keywords: k, Extensions: ext, Assignment: regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|credential|private[_-]?key)[A-Za-z0-9_.-]*)\s*[:=]\s*([^\s,;]+)`), PrivateKey: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), EntropyMin: 4.2}
}
func (c *Config) LoadKeywords(file string) error {
	f, e := os.Open(file)
	if e != nil {
		return e
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			c.Keywords[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		} else {
			c.Keywords[strings.ToLower(line)] = "custom"
		}
	}
	return s.Err()
}

type Match struct {
	Category, Keyword, Evidence string
	Confidence                  int
	Line                        int
}

func (c Config) Detect(content []byte) []Match {
	if len(content) == 0 || strings.IndexByte(string(content), 0) >= 0 {
		return nil
	}
	text := strings.ToValidUTF8(string(content), "�")
	lines := strings.Split(text, "\n")
	out := []Match{}
	seen := map[string]bool{}
	for i, line := range lines {
		low := strings.ToLower(line)
		for kw, cat := range c.Keywords {
			if strings.Contains(low, kw) {
				key := cat + "|" + kw + "|" + string(rune(i+1))
				if !seen[key] {
					seen[key] = true
					out = append(out, Match{cat, kw, redact(line), 55, i + 1})
				}
			}
		}
		for _, m := range c.Assignment.FindAllStringSubmatch(line, 4) {
			key := strings.ToLower(m[1])
			cat := "credential-like"
			for kw, v := range c.Keywords {
				if strings.Contains(key, kw) {
					cat = v
					break
				}
			}
			out = append(out, Match{cat, key, redact(line), 85, i + 1})
		}
		if c.PrivateKey.MatchString(line) {
			out = append(out, Match{"private-key-header", "private-key", "[REDACTED PRIVATE KEY HEADER]", 98, i + 1})
		}
	}
	return dedupe(out)
}
func redact(s string) string {
	if len(s) > 500 {
		s = s[:500] + "…"
	}
	return regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|credential)(\s*[:=]\s*)[^\s,;]+`).ReplaceAllString(s, "$1$2[REDACTED]")
}
func dedupe(in []Match) []Match {
	o := []Match{}
	seen := map[string]bool{}
	for _, m := range in {
		k := m.Category + m.Keyword + m.Evidence + string(rune(m.Line))
		if !seen[k] {
			seen[k] = true
			o = append(o, m)
		}
	}
	return o
}
func Fingerprint(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
