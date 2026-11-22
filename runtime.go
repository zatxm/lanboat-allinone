// Package allinone exposes the independently implemented Lanboat networking core.
package allinone

import (
	"context"

	"github.com/zatxm/lanboat-allinone/v26/native"
	"go.uber.org/zap"
)

const Version = native.Version

// RunTailscaleSSHWorker dispatches credential-dropped SSH workers before a GUI starts.
func RunTailscaleSSHWorker(args []string) (bool, error) { return native.RunTailscaleSSHWorker(args) }

// RunNetworkNamespaceWorker dispatches Linux namespace resource helpers before a GUI starts.
func RunNetworkNamespaceWorker(args []string) (bool, error) {
	return native.RunNetworkNamespaceWorker(args)
}

type DNSLog = native.DNSLog
type RequestLog = native.RequestLog
type ConnectionLog = native.ConnectionLog
type ConnectionEvent = native.ConnectionEvent

const (
	ConnectionOpened = native.ConnectionOpened
	ConnectionFailed = native.ConnectionFailed
	ConnectionClosed = native.ConnectionClosed
)

const RequestBodyLogLimit = native.RequestBodyLogLimit

type Runtime = native.Runtime
type TengoFunction = native.TengoFunction
type TengoProgram = native.TengoProgram

func NewTengoProgram(source string, modules map[string]map[string]TengoFunction) (*TengoProgram, error) {
	return native.NewTengoProgram(source, modules)
}

type Metadata = native.Metadata
type RelayForward = native.RelayForward
type TailscaleStatus = native.TailscaleStatus
type SudokuUserStat = native.SudokuUserStat
type OpenConnectAuthHandler = native.OpenConnectAuthHandler
type OpenConnectAuthForm = native.OpenConnectAuthForm
type OpenConnectAuthField = native.OpenConnectAuthField
type OpenConnectAuthOption = native.OpenConnectAuthOption
type OpenConnectAuthRequiredError = native.OpenConnectAuthRequiredError
type OpenConnectSSO = native.OpenConnectSSO
type OpenConnectHostScan = native.OpenConnectHostScan
type OpenConnectHostScanResponse = native.OpenConnectHostScanResponse
type OpenConnectNegotiateSession = native.OpenConnectNegotiateSession
type OpenConnectNegotiateRequest = native.OpenConnectNegotiateRequest
type OpenConnectNegotiateHandler = native.OpenConnectNegotiateHandler

func WithOpenConnectNegotiate(ctx context.Context, handler OpenConnectNegotiateHandler) context.Context {
	return native.WithOpenConnectNegotiate(ctx, handler)
}

func WithOpenConnectAuth(ctx context.Context, handler OpenConnectAuthHandler) context.Context {
	return native.WithOpenConnectAuth(ctx, handler)
}

type MasqueNameserver = native.MasqueNameserver
type MasqueDNSConfiguration = native.MasqueDNSConfiguration
type MasqueNetworkConfiguration = native.MasqueNetworkConfiguration
type MasquePathStatus = native.MasquePathStatus

func WithMetadata(ctx context.Context, metadata Metadata) context.Context {
	return native.WithMetadata(ctx, metadata)
}

func New(ctx context.Context, config []byte) (*Runtime, error) {
	return native.New(ctx, config, nil)
}

func NewWithLogger(ctx context.Context, config []byte, logger *zap.Logger) (*Runtime, error) {
	return native.New(ctx, config, logger)
}

func Check(ctx context.Context, config []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := native.Parse(config)
	return err
}

// CompileRuleSet compiles source JSON or AdGuard domain filters to SRSv5.
func CompileRuleSet(input []byte, format string) ([]byte, error) {
	return native.CompileRuleSet(input, format)
}

// GenerateRealityKeyPair returns a new X25519 private/public key pair in
// unpadded base64url, compatible with Reality configuration fields.
func GenerateRealityKeyPair() (private, public string, err error) {
	return native.GenerateRealityKeyPair()
}

// GenerateRealityMLDSA65KeyPair returns the optional Reality ML-DSA-65 seed
// and public verification key in unpadded base64url.
func GenerateRealityMLDSA65KeyPair() (seed, public string, err error) {
	return native.GenerateRealityMLDSA65KeyPair()
}

func DecodeRuleSet(data []byte) ([]byte, error) { return native.DecodeRuleSet(data) }

func MatchRuleSet(data []byte, target string) (bool, error) { return native.MatchRuleSet(data, target) }
