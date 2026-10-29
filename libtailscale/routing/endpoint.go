//go:build with_gvisor

// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"context"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func (p *packetPort) WritePacket(packet *stack.PacketBuffer) (int, error) {
	data := make([]byte, 0, packet.Size())
	for _, part := range packet.AsSlices() {
		data = append(data, part...)
	}
	return p.Write(data)
}
func (p *packetPort) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	endpoint := channel.New(256, 1280, "")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-p.done; cancel(); endpoint.Close() }()
	go func() {
		for {
			select {
			case <-p.done:
				return
			case data := <-p.packets:
				if len(data) == 0 {
					continue
				}
				packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
				switch data[0] >> 4 {
				case 4:
					endpoint.InjectInbound(header.IPv4ProtocolNumber, packet)
				case 6:
					endpoint.InjectInbound(header.IPv6ProtocolNumber, packet)
				}
				packet.DecRef()
			}
		}
	}()
	go func() {
		for {
			packet := endpoint.ReadContext(ctx)
			if packet == nil {
				return
			}
			p.WritePacket(packet)
			packet.DecRef()
		}
	}()
	return endpoint, stack.NICOptions{}, nil
}
