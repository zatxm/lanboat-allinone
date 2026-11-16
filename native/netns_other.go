//go:build !linux

package native

import (
	"context"
	"errors"
	"net"
)

type networkNamespace struct{}

func (*networkNamespace) matches(string) bool { return false }

func startNamespace(context.Context, NetworkNamespaceOptions, Route) (*networkNamespace, error) {
	return nil, errors.New("network namespaces require Linux")
}
func (*networkNamespace) close() {}
func (*networkNamespace) dial(context.Context, DialOptions, string, string) (net.Conn, error) {
	return nil, errors.New("network namespaces require Linux")
}
func (*networkNamespace) listen(context.Context, ListenOptions, string, string) (net.Listener, error) {
	return nil, errors.New("network namespaces require Linux")
}
func (*networkNamespace) packet(context.Context, DialOptions, ListenOptions, string, string, string, bool) (net.PacketConn, error) {
	return nil, errors.New("network namespaces require Linux")
}
func RunNetworkNamespaceWorker(args []string) (bool, error) { return false, nil }
func (*tunTunnel) refreshNamespaceAddresses()               {}
func (*tunTunnel) namespaceNetworkKey() string              { return "" }
func (*tunTunnel) startFilter()                             {}
func (*networkNamespace) processIdentity(context.Context, *processFinder, socketOrigin, bool) Metadata {
	return Metadata{}
}
func (*networkNamespace) neighborIdentity(context.Context, string, []string) Metadata {
	return Metadata{}
}

func (*networkNamespace) networkChoices(context.Context) ([]networkChoice, error) {
	return nil, errors.New("network namespaces require Linux")
}
