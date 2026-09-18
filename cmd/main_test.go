package main

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	credentialcomposerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/credentialcomposer/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const passthroughJWT = `spire.plugin.server.credentialcomposer.v1.ComposeWorkloadJWTSVIDResponse{}`
const passthroughX509 = `spire.plugin.server.credentialcomposer.v1.ComposeWorkloadX509SVIDResponse{}`

// Keeps the configured ca_subject but drops the serial number SPIRE adds by
// default, so the CA subject DN is stable across CA rotations.
const stableCASubject = `
spire.plugin.server.credentialcomposer.v1.ComposeServerX509CAResponse{
  attributes: spire.plugin.server.credentialcomposer.v1.X509CAAttributes{
    subject: spire.plugin.server.credentialcomposer.v1.DistinguishedName{
      country: x509_ca_request.attributes.subject.country,
      organization: x509_ca_request.attributes.subject.organization,
      common_name: x509_ca_request.attributes.subject.common_name
    },
    policy_identifiers: x509_ca_request.attributes.policy_identifiers,
    extra_extensions: x509_ca_request.attributes.extra_extensions
  }
}`

func configure(t *testing.T, hcl string) *Plugin {
	t.Helper()
	p := new(Plugin)
	p.SetLogger(hclog.NewNullLogger())
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  hcl,
	})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	return p
}

func caRequest() *credentialcomposerv1.ComposeServerX509CARequest {
	return &credentialcomposerv1.ComposeServerX509CARequest{
		Attributes: &credentialcomposerv1.X509CAAttributes{
			Subject: &credentialcomposerv1.DistinguishedName{
				Country:      []string{"DE"},
				Organization: []string{"okrim"},
				CommonName:   "example.org",
				SerialNumber: "313309170946026008969923951168654900271",
			},
			PolicyIdentifiers: []string{"1.2.3"},
		},
	}
}

func TestComposeServerX509CAUnconfigured(t *testing.T) {
	p := configure(t, `
jwt { expression_string = "`+passthroughJWT+`" }
x509 { expression_string = "`+passthroughX509+`" }
`)
	_, err := p.ComposeServerX509CA(context.Background(), caRequest())
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented without x509_ca block, got %v", err)
	}
}

func TestComposeServerX509CADropsSerial(t *testing.T) {
	p := configure(t, `
jwt { expression_string = "`+passthroughJWT+`" }
x509 { expression_string = "`+passthroughX509+`" }
x509_ca { expression_string = <<EOB
`+stableCASubject+`
EOB
}
`)
	resp, err := p.ComposeServerX509CA(context.Background(), caRequest())
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	subj := resp.GetAttributes().GetSubject()
	if subj.GetSerialNumber() != "" {
		t.Errorf("serial number should be dropped, got %q", subj.GetSerialNumber())
	}
	if subj.GetCommonName() != "example.org" {
		t.Errorf("common name not preserved: %q", subj.GetCommonName())
	}
	if len(subj.GetCountry()) != 1 || subj.GetCountry()[0] != "DE" {
		t.Errorf("country not preserved: %v", subj.GetCountry())
	}
	if len(subj.GetOrganization()) != 1 || subj.GetOrganization()[0] != "okrim" {
		t.Errorf("organization not preserved: %v", subj.GetOrganization())
	}
	if len(resp.GetAttributes().GetPolicyIdentifiers()) != 1 {
		t.Errorf("policy identifiers not preserved: %v", resp.GetAttributes().GetPolicyIdentifiers())
	}
}

func TestComposeServerX509CABadExpression(t *testing.T) {
	p := new(Plugin)
	p.SetLogger(hclog.NewNullLogger())
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration: `
jwt { expression_string = "` + passthroughJWT + `" }
x509 { expression_string = "` + passthroughX509 + `" }
x509_ca { expression_string = "this is not cel" }
`,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for broken x509_ca expression, got %v", err)
	}
}
