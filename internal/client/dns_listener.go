// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"net"
	"time"

	"masterdnsvpn-go/internal/dnscache"
	"masterdnsvpn-go/internal/dnsparser"
)

type DNSListener struct {
	client   *Client
	conn     *net.UDPConn
	stopChan chan struct{}
}

func NewDNSListener(c *Client) *DNSListener {
	return &DNSListener{
		client:   c,
		stopChan: make(chan struct{}),
	}
}

func (l *DNSListener) Start(ctx context.Context, ip string, port int) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	l.conn = conn

	l.client.log.Infof("🚀 <green>DNS server is listening on <cyan>%s:%d</cyan></green>", ip, port)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, peerAddr, err := l.conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-l.stopChan:
					return
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			// Copy data for the handler to prevent overwrite race condition
			dataCopy := make([]byte, n)
			copy(dataCopy, buf[:n])
			go l.handleQuery(ctx, dataCopy, peerAddr)
		}
	}()

	return nil
}

func (l *DNSListener) Stop() {
	close(l.stopChan)
	if l.conn != nil {
		_ = l.conn.Close()
	}
}

// handleQuery manages incoming DNS queries by checking the local cache or redirecting to the tunnel.
func (l *DNSListener) handleQuery(ctx context.Context, data []byte, addr *net.UDPAddr) {
	if l.client == nil {
		return
	}

	// 1. Lite Parse DNS Query
	lite, err := dnsparser.ParseDNSRequestLite(data)
	if err != nil {
		return
	}

	if !lite.HasQuestion {
		return
	}

	question := lite.FirstQuestion
	now := time.Now()

	// 2. Check Local Cache & Handle Pending Status
	if l.client.localDNSCache != nil {
		key := dnscache.BuildKey(question.Name, question.Type, question.Class)
		res := l.client.localDNSCache.LookupOrCreatePending(key, question.Name, question.Type, question.Class, now)

		if res.Status == dnscache.StatusReady && len(res.Response) > 0 {
			// Cache Hit - Rewrite Transaction ID and send back
			resp := dnscache.PatchResponseForQuery(res.Response, data)
			_, _ = l.conn.WriteToUDP(resp, addr)
			l.client.log.Debugf("🔍 <green>DNS Cache Hit: %s (%d)</green>", question.Name, question.Type)
			return
		}

		if res.Status == dnscache.StatusPending && !res.DispatchNeeded {
			// Already pending in tunnel and within timeout, don't re-dispatch
			l.client.log.Debugf("🔍 <yellow>DNS Query Pending: %s (%d)</yellow>", question.Name, question.Type)
			return
		}

		// If res.DispatchNeeded is true, we proceed to tunnel dispatch
	}

	// 3. Dispatch to Tunnel
	l.client.dispatchDNSQueryToTunnel(data, addr)
}
