// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic and initialization for the MasterDnsVPN client.
// This file (dns_tunnel.go) handles DNS query dispatching through the tunnel.
// ==============================================================================
package client

import (
	"net"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (c *Client) dispatchDNSQueryToTunnel(query []byte, addr *net.UDPAddr) {
	if !c.SessionReady() {
		return
	}

	c.streamsMu.RLock()
	s0, ok := c.active_streams[0]
	c.streamsMu.RUnlock()

	if !ok || s0 == nil {
		return
	}

	arqObj, ok := s0.Stream.(*arq.ARQ)
	if !ok {
		return
	}

	// Calculate target MTU for fragments
	// DNS header + encoded labels overhead is handled by BuildEncodedAuto/buildTunnelTXTQuestion
	// but we need to ensure the raw VPN payload fits.
	mtu := c.syncedUploadMTU - VpnProto.MaxHeaderRawSize()
	if mtu < 100 {
		mtu = 120 // Absolute minimum fallback
	}

	fragments := fragmentPayload(query, mtu)
	total := uint8(len(fragments))

	// Generate a unique sequence number for this DNS query
	sn := uint16(c.mtuProbeCounter.Add(1) & 0xFFFF)

	// Store the waiter by sequence number
	c.dnsWaiters.Store(sn, addr)

	for i, frag := range fragments {
		fragID := uint8(i)

		// Send via ARQ as a control packet
		// ARQ.SendControlPacket will track and retransmit if it's in ControlAckPairs.
		arqObj.SendControlPacket(Enums.PACKET_DNS_QUERY_REQ, sn, fragID, total, frag, 3, true, nil)
	}

	if c.log != nil {
		c.log.Infof("🧳 <green>DNS Query Redirected to Tunnel: <cyan>%d</cyan> bytes, <cyan>%d</cyan> fragments (Seq: <cyan>%d</cyan>)</green>", len(query), total, sn)
	}
}
