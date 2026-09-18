package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	credentialcomposerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/credentialcomposer/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

type ConfigCEL struct {
	ExpressionString *string `hcl:"expression_string"`
	ExpressionPath   *string `hcl:"expression_path"`
	prg              cel.Program
}

type Config struct {
	JWT  ConfigCEL `hcl:"jwt"`
	X509 ConfigCEL `hcl:"x509"`
	// Optional. When unset, ComposeServerX509CA stays unimplemented and the
	// server keeps its default CA subject.
	X509CA            ConfigCEL `hcl:"x509_ca"`
	trustDomain       string
	spiffeTrustDomain string
}

type Plugin struct {
	credentialcomposerv1.UnsafeCredentialComposerServer
	configv1.UnimplementedConfigServer
	configMtx sync.RWMutex
	config    *Config
	logger    hclog.Logger
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	config.trustDomain = req.CoreConfiguration.TrustDomain
	config.spiffeTrustDomain = fmt.Sprintf("spiffe://%s", config.trustDomain)

	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	if config.JWT.ExpressionString == nil && config.JWT.ExpressionPath == nil {
		return nil, status.Errorf(codes.InvalidArgument, "you must have jwt.expression_string or jwt.expression_path defined.")
	}

	if config.X509.ExpressionString == nil && config.X509.ExpressionPath == nil {
		return nil, status.Errorf(codes.InvalidArgument, "you must have X509.expression_string or X509.expression_path defined.")
	}

	if err := loadExpressionFromPath(&config.JWT); err != nil {
		return nil, err
	}

	if err := loadExpressionFromPath(&config.X509); err != nil {
		return nil, err
	}

	dynType := cel.MapType(cel.DynType, cel.DynType)
	env, err := cel.NewEnv(
		cel.Types(&credentialcomposerv1.ComposeWorkloadJWTSVIDRequest{}),
		cel.Types(&credentialcomposerv1.ComposeWorkloadJWTSVIDResponse{}),
		cel.Types(&credentialcomposerv1.ComposeWorkloadX509SVIDRequest{}),
		cel.Types(&credentialcomposerv1.ComposeWorkloadX509SVIDResponse{}),
		cel.Types(&credentialcomposerv1.ComposeServerX509CARequest{}),
		cel.Types(&credentialcomposerv1.ComposeServerX509CAResponse{}),
		cel.Types(&structpb.Struct{}),
		cel.Variable("trust_domain", cel.StringType),
		cel.Variable("spiffe_trust_domain", cel.StringType),
		cel.Variable("jwt_request", cel.ObjectType("spire.plugin.server.credentialcomposer.v1.ComposeWorkloadJWTSVIDRequest")),
		cel.Variable("x509_request", cel.ObjectType("spire.plugin.server.credentialcomposer.v1.ComposeWorkloadX509SVIDRequest")),
		cel.Variable("x509_ca_request", cel.ObjectType("spire.plugin.server.credentialcomposer.v1.ComposeServerX509CARequest")),
		ext.Bindings(),
		ext.Lists(),
		ext.Strings(),
		ext.TwoVarComprehensions(),
		cel.Function("mapOverrideEntries",
			cel.MemberOverload("mapOverrideEntries",
				[]*cel.Type{dynType, dynType},
				dynType,
				cel.FunctionBinding(mapOverrideEntries),
			),
		),
		cel.Function("uuidgen",
			cel.Overload("uuidgen",
				[]*cel.Type{},
				cel.StringType,
				cel.FunctionBinding(uuidgen),
			),
		),
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to load cel environment: %v", err)
	}

	ast, issues := env.Compile(*config.JWT.ExpressionString)
	if issues != nil && issues.Err() != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to compile cel expression: %v", issues.Err())
	}

	prg, err := env.Program(ast)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to build cel program: %v", err)
	}
	config.JWT.prg = prg

	astX509, issuesX509 := env.Compile(*config.X509.ExpressionString)
	if issuesX509 != nil && issuesX509.Err() != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to compile cel expression for X509: %v", issuesX509.Err())
	}

	prgX509, err := env.Program(astX509)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to build cel program for X509: %v", err)
	}
	config.X509.prg = prgX509

	if config.X509CA.ExpressionString != nil || config.X509CA.ExpressionPath != nil {
		if err := loadExpressionFromPath(&config.X509CA); err != nil {
			return nil, err
		}
		astX509CA, issuesX509CA := env.Compile(*config.X509CA.ExpressionString)
		if issuesX509CA != nil && issuesX509CA.Err() != nil {
			return nil, status.Errorf(codes.InvalidArgument, "Failed to compile cel expression for X509 CA: %v", issuesX509CA.Err())
		}
		prgX509CA, err := env.Program(astX509CA)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "Failed to build cel program for X509 CA: %v", err)
		}
		config.X509CA.prg = prgX509CA
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) ComposeServerX509CA(_ context.Context, req *credentialcomposerv1.ComposeServerX509CARequest) (*credentialcomposerv1.ComposeServerX509CAResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}
	if config.X509CA.prg == nil {
		// No x509_ca expression configured: behave as before.
		return nil, status.Error(codes.Unimplemented, "not implemented")
	}
	p.logger.Debug("x509 CA rewrite request", req)
	out, _, err := config.X509CA.prg.Eval(map[string]interface{}{
		"trust_domain":        config.trustDomain,
		"spiffe_trust_domain": config.spiffeTrustDomain,
		"x509_ca_request":     req,
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to evaluate cel expression: %v", err)
	}
	respn, err := out.ConvertToNative(reflect.TypeOf(&credentialcomposerv1.ComposeServerX509CAResponse{}))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to parse return type: %v", err)
	}
	resp, _ := respn.(*credentialcomposerv1.ComposeServerX509CAResponse)
	p.logger.Debug("x509 CA rewrite response", resp)
	return resp, nil
}

func (p *Plugin) ComposeServerX509SVID(context.Context, *credentialcomposerv1.ComposeServerX509SVIDRequest) (*credentialcomposerv1.ComposeServerX509SVIDResponse, error) {
	// Intentionally not implemented.
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) ComposeAgentX509SVID(context.Context, *credentialcomposerv1.ComposeAgentX509SVIDRequest) (*credentialcomposerv1.ComposeAgentX509SVIDResponse, error) {
	// Intentionally not implemented.
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) ComposeWorkloadX509SVID(_ context.Context, req *credentialcomposerv1.ComposeWorkloadX509SVIDRequest) (*credentialcomposerv1.ComposeWorkloadX509SVIDResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}
	p.logger.Debug("x509 rewrite request", req)
	out, _, err := config.X509.prg.Eval(map[string]interface{}{
		"trust_domain":        config.trustDomain,
		"spiffe_trust_domain": config.spiffeTrustDomain,
		"x509_request":        req,
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to evaluate cel expression: %v", err)
	}
	respn, err := out.ConvertToNative(reflect.TypeOf(&credentialcomposerv1.ComposeWorkloadX509SVIDResponse{}))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to parse return type: %v", err)
	}
	resp, _ := respn.(*credentialcomposerv1.ComposeWorkloadX509SVIDResponse)
	p.logger.Debug("x509 rewrite response", resp)
	return resp, nil
}

func (p *Plugin) ComposeWorkloadJWTSVID(_ context.Context, req *credentialcomposerv1.ComposeWorkloadJWTSVIDRequest) (*credentialcomposerv1.ComposeWorkloadJWTSVIDResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}
	p.logger.Debug("JWT rewrite request", req)
	out, _, err := config.JWT.prg.Eval(map[string]interface{}{
		"trust_domain":        config.trustDomain,
		"spiffe_trust_domain": config.spiffeTrustDomain,
		"jwt_request":         req,
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to evaluate cel expression: %v", err)
	}
	respn, err := out.ConvertToNative(reflect.TypeOf(&credentialcomposerv1.ComposeWorkloadJWTSVIDResponse{}))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to parse return type: %v", err)
	}
	resp, _ := respn.(*credentialcomposerv1.ComposeWorkloadJWTSVIDResponse)
	p.logger.Debug("JWT rewrite response", resp)
	return resp, nil
}

func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func mapOverrideEntries(args ...ref.Val) ref.Val {
	lhs := args[0]
	rhs := args[1]

	copy := make(map[ref.Val]ref.Val, 0)
	mapper, ok := lhs.(traits.Mapper)
	if !ok {
		return types.ValOrErr(nil, "unsupported lhs type")
	}
	it := mapper.Iterator()
	for it.HasNext() == types.True {
		nextK := it.Next()
		nextV := mapper.Get(nextK)
		copy[nextK] = nextV
	}
	mapper, ok = rhs.(traits.Mapper)
	if !ok {
		return types.ValOrErr(nil, "unsupported rhs type")
	}
	it = mapper.Iterator()
	for it.HasNext() == types.True {
		nextK := it.Next()
		nextV := mapper.Get(nextK)
		copy[nextK] = nextV
	}
	return types.DefaultTypeAdapter.NativeToValue(copy)
}

func loadExpressionFromPath(config *ConfigCEL) error {
	if config.ExpressionPath == nil {
		return nil
	}
	file, err := os.Open(*config.ExpressionPath)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "Error opening file: %v", err)
	}
	defer func() {
		_ = file.Close()
	}()
	data, err := io.ReadAll(file)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "Error reading file: %v", err)
	}
	str := string(data)
	config.ExpressionString = &str
	return nil
}

func uuidgen(args ...ref.Val) ref.Val {
	return types.String(uuid.New().String())
}

func main() {
	plugin := new(Plugin)
	pluginmain.Serve(
		credentialcomposerv1.CredentialComposerPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
