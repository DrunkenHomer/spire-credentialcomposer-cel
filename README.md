# SPIRE Credential Composer CEL

[![Apache 2.0 License](https://img.shields.io/github/license/spiffe/helm-charts)](https://opensource.org/licenses/Apache-2.0)
[![Development Phase](https://github.com/spiffe/spiffe/blob/main/.img/maturity/dev.svg)](https://github.com/spiffe/spiffe/blob/main/MATURITY.md#development)

This project enables SPIRE Credential Composers to be written in [CEL](https://cel.dev/)

## Warning

This code is very early in development and is very experimental. Please do not use it in production yet. Please do consider testing it out, provide feedback, and maybe provide fixes.

## JWT Expressions

### Environment

The following root level variables are defined:
 * request - spire.plugin.server.credentialcomposer.v1.ComposeWorkloadJWTSVIDRequest
 * trust_domain - string, the trust domain of the server
 * spiffe_trust_domain - string, the trust domain in spiffe://<trust_domain> format

request has the following properties:
 * spiffe_id - string
 * attributes - spire.plugin.server.credentialcomposer.v1.JWTSVIDAttributes

request.attributes has the following properties:
 * claims - map(dyn, dyn)

### Macros

The standard macros are [available](https://github.com/google/cel-spec/blob/master/doc/langdef.md#macros).

Some ext macros are also availabe:
 * [cel.bind](https://pkg.go.dev/github.com/google/cel-go/ext#hdr-Cel_Bind-Bindings)
 * [strings](https://pkg.go.dev/github.com/google/cel-go/ext#Strings)
 * [two var comprehensions](https://pkg.go.dev/github.com/google/cel-go/ext#TwoVarComprehensions)

Custom macros are provided:
 * mapOverrideEntries - Runs on a map, give it another map and it will override settings in the first map with the second. It is a shallow override, no merging is performed.
 * uuidgen - generate a v4(random) uuid

### Return

Currently only the `spire.plugin.server.credentialcomposer.v1.ComposeWorkloadJWTSVIDResponse` type is
supported. It must be completely filled out. Other shortcut options may be added in the future.

## JWT Examples

### Add a new claim

This example adds `newkey=newvalue` to the token.

```
  CredentialComposer "cel" {
    plugin_cmd = "spire-credentialcomposer-cel"
    plugin_checksum = ""
    plugin_data {
      jwt {
        expression_string = <<EOB
spire.plugin.server.credentialcomposer.v1.ComposeWorkloadJWTSVIDResponse{
  attributes: spire.plugin.server.credentialcomposer.v1.JWTSVIDAttributes{
    claims: request.attributes.claims.mapOverrideEntries({
      'newkey': "newvalue"
    })
  }
}
EOB
      }
    }
  }
```

### JTI

Some clients want a JTI property. Add one.

SPIRE Server Config:
```
  CredentialComposer "cel" {
    plugin_cmd = "spire-credentialcomposer-cel"
    plugin_checksum = ""
    plugin_data {
      jwt {
        expression_string = <<EOB
spire.plugin.server.credentialcomposer.v1.ComposeWorkloadJWTSVIDResponse{
  attributes: spire.plugin.server.credentialcomposer.v1.JWTSVIDAttributes{
    claims: request.attributes.claims.mapOverrideEntries({"jti": uuidgen()})
  }
}
EOB
      }
    }
  }
```

### Minio

In this example, we conditionally add a policy propery that is a list of properties as per the Minio OIDC 
documentation. The spiffe id path must start with /minio/ and everything after will be used as the policy
name.

For example, spiffe://example.org/minio/readonly will add to the token `policy: ["readonly"]`.

SPIRE Server Config:
```
  CredentialComposer "cel" {
    plugin_cmd = "spire-credentialcomposer-cel"
    plugin_checksum = ""
    plugin_data {
      jwt {
        expression_string = <<EOB
spire.plugin.server.credentialcomposer.v1.ComposeWorkloadJWTSVIDResponse{
  attributes: spire.plugin.server.credentialcomposer.v1.JWTSVIDAttributes{
    claims: request.attributes.claims.mapOverrideEntries(
      request.spiffe_id.startsWith(spiffe_trust_domain + "/minio/")?
      {'policy': [request.spiffe_id.substring(spiffe_trust_domain.size() + 7)]}:
      {}
    )
  }
}
EOB
      }
    }
  }
```

## X509 CA Expressions

Optional. Set an `x509_ca` block to run a CEL expression when the server
composes its own X509 CA certificate (`ComposeServerX509CA`). Without the block
the plugin reports the hook as unimplemented and SPIRE keeps its default.

### Environment

 * x509_ca_request - spire.plugin.server.credentialcomposer.v1.ComposeServerX509CARequest
 * trust_domain, spiffe_trust_domain - as above

x509_ca_request.attributes has the following properties:
 * subject - spire.plugin.server.credentialcomposer.v1.DistinguishedName
 * policy_identifiers - list(string)
 * extra_extensions - list(spire.plugin.server.credentialcomposer.v1.X509Extension)

### Return

`spire.plugin.server.credentialcomposer.v1.ComposeServerX509CAResponse`. As with the
other hooks, the returned attributes replace the request attributes entirely, so
pass through everything you do not intend to change.

### Stable CA subject DN

By default SPIRE appends the certificate serial number to the CA subject
(`serialNumber=...`), so the subject DN changes on every CA rotation. Consumers
that pin the issuer DN (for example Keycloak's `x509.casubjectdn`) need a
stable one. This keeps the configured `ca_subject` and drops the serial:

```
  CredentialComposer "cel" {
    plugin_cmd = "spire-credentialcomposer-cel"
    plugin_checksum = ""
    plugin_data {
      jwt  { expression_string = "spire.plugin.server.credentialcomposer.v1.ComposeWorkloadJWTSVIDResponse{}" }
      x509 { expression_string = "spire.plugin.server.credentialcomposer.v1.ComposeWorkloadX509SVIDResponse{}" }
      x509_ca {
        expression_string = <<EOB
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
}
EOB
      }
    }
  }
```

## CEL Hints

### Setting a variable:
```
cel.bind(varname, valueforvar,
  logic here
)
```

### Remove a specific item from a map
```
X.transformMap(k, v, k != 'abc', v)
```

### Update an existing item in a map:
```
X.transformMap(k, v, k == 'abc'? 72: v)
```

