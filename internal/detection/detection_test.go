package detection

import "testing"

func TestDetectRedactsPassword(t *testing.T) {
	c := DefaultConfig()
	m := c.Detect([]byte("db_password=SuperSecret123\n"))
	if len(m) == 0 {
		t.Fatal("expected finding")
	}
	for _, x := range m {
		if x.Evidence == "db_password=SuperSecret123" {
			t.Fatal("secret was not redacted")
		}
	}
}
func TestDetectPrivateKeyHeader(t *testing.T) {
	c := DefaultConfig()
	m := c.Detect([]byte("-----BEGIN RSA PRIVATE KEY-----\n"))
	found := false
	for _, x := range m {
		if x.Category == "private-key-header" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected private key header finding")
	}
}
