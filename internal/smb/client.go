package smb

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/breachoperators/sharehunter/internal/auth"
	smb2 "github.com/hirochachacha/go-smb2"
)

type Client struct {
	conn    net.Conn
	session *smb2.Session
}

func Connect(ctx context.Context, host string, c auth.Credentials, timeout time.Duration) (*Client, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "445"))
	if err != nil {
		return nil, err
	}
	initiator := &smb2.NTLMInitiator{User: c.Username, Password: c.Password, Domain: c.Domain}
	if c.Mode == "none" {
		// go-smb2 v1 does not support a truly anonymous NTLM session; this
		// requests the server's Guest mapping, if the server permits it.
		initiator = &smb2.NTLMInitiator{User: "Guest", Password: ""}
	}
	dialer := &smb2.Dialer{Initiator: initiator}
	sess, err := dialer.DialContext(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SMB session: %w", err)
	}
	return &Client{conn: conn, session: sess.WithContext(ctx)}, nil
}
func (c *Client) Shares() ([]string, error)              { return c.session.ListSharenames() }
func (c *Client) Mount(name string) (*smb2.Share, error) { return c.session.Mount(name) }
func (c *Client) Unmount(share *smb2.Share) error        { return share.Umount() }
func (c *Client) Close() {
	if c.session != nil {
		_ = c.session.Logoff()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
}
