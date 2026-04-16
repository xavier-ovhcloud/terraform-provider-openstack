// Package openstack provides Terraform provider support for OIDC authentication
// against OpenStack Keystone v3.
//
// This file integrates gophercloud's new OIDC auth types into the Terraform
// OpenStack provider, allowing users to configure:
//
//   - v3oidcclientcredentials
//   - v3oidcpassword
//   - v3oidcauthcode
//   - v3oidcaccesstoken
//
// via provider HCL or environment variables.
//
// Provider HCL example (OVHcloud IAM):
//
//	provider "openstack" {
//	  auth_url          = "https://auth.cloud.ovh.net/v3"
//	  auth_type         = "v3oidcclientcredentials"
//	  identity_provider = "ovhcloud-emea"
//	  protocol          = "openid"
//	  discovery_endpoint = "https://iam.ovh.net/role-adapter/.../openid-configuration"
//	  client_id         = var.client_id
//	  client_secret     = var.client_secret
//	  openid_scope      = "openid profile email publicCloudProject/all"
//	  access_token_type = "id_token"
//	  project_id        = var.project_id
//	  region            = "GRA11"
//	}
//
// Environment variable equivalents:
//
//	OS_AUTH_TYPE=v3oidcclientcredentials
//	OS_IDENTITY_PROVIDER=ovhcloud-emea
//	OS_PROTOCOL=openid
//	OS_DISCOVERY_ENDPOINT=https://iam.ovh.net/role-adapter/.../openid-configuration
//	OS_CLIENT_ID=...
//	OS_CLIENT_SECRET=...
//	OS_OPENID_SCOPE=openid profile email publicCloudProject/all
//	OS_ACCESS_TOKEN_TYPE=id_token
//	OS_PROJECT_ID=...
package openstack

import (
	"context"
	"fmt"
	"os"

	"github.com/gophercloud/gophercloud/v2"
	clientconfig "github.com/gophercloud/utils/v2/openstack/clientconfig"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// oidcProviderSchema returns the schema attributes added to the OpenStack
// provider for OIDC authentication support.
//
// These are merged into the main provider schema alongside the existing
// attributes (auth_url, username, password, etc.).
func oidcProviderSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"auth_type": {
			Type:        schema.TypeString,
			Optional:    true,
			DefaultFunc: schema.EnvDefaultFunc("OS_AUTH_TYPE", ""),
			Description: "Authentication type. Supported OIDC values: " +
				"v3oidcclientcredentials, v3oidcpassword, v3oidcauthcode, v3oidcaccesstoken. " +
				"Can also be set with OS_AUTH_TYPE.",
		},
		"identity_provider": {
			Type:        schema.TypeString,
			Optional:    true,
			DefaultFunc: schema.EnvDefaultFunc("OS_IDENTITY_PROVIDER", ""),
			Description: "Name of the identity provider registered in Keystone " +
				"(e.g. 'ovhcloud-emea', 'atmosphere'). Required for OIDC auth. " +
				"Can also be set with OS_IDENTITY_PROVIDER.",
		},
		"protocol": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "openid",
			DefaultFunc: schema.EnvDefaultFunc("OS_PROTOCOL", "openid"),
			Description: "Federation protocol registered in Keystone (default: openid). " +
				"Can also be set with OS_PROTOCOL.",
		},
		"discovery_endpoint": {
			Type:        schema.TypeString,
			Optional:    true,
			DefaultFunc: schema.EnvDefaultFunc("OS_DISCOVERY_ENDPOINT", ""),
			Description: "OIDC discovery endpoint URL (.well-known/openid-configuration). " +
				"Either discovery_endpoint or token_endpoint must be set for OIDC auth. " +
				"Can also be set with OS_DISCOVERY_ENDPOINT.",
		},
		"token_endpoint": {
			Type:        schema.TypeString,
			Optional:    true,
			DefaultFunc: schema.EnvDefaultFunc("OS_TOKEN_ENDPOINT", ""),
			Description: "OIDC token endpoint URL. Overrides discovery_endpoint if set. " +
				"Can also be set with OS_TOKEN_ENDPOINT.",
		},
		"client_id": {
			Type:        schema.TypeString,
			Optional:    true,
			DefaultFunc: schema.EnvDefaultFunc("OS_CLIENT_ID", ""),
			Description: "OIDC client ID. " +
				"Can also be set with OS_CLIENT_ID.",
		},
		"client_secret": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			DefaultFunc: schema.EnvDefaultFunc("OS_CLIENT_SECRET", ""),
			Description: "OIDC client secret. " +
				"Can also be set with OS_CLIENT_SECRET.",
		},
		"openid_scope": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "openid",
			DefaultFunc: schema.EnvDefaultFunc("OS_OPENID_SCOPE", "openid"),
			Description: "Space-separated list of OIDC scopes to request " +
				"(e.g. 'openid profile email publicCloudProject/all'). " +
				"Can also be set with OS_OPENID_SCOPE.",
		},
		"access_token_type": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "access_token",
			DefaultFunc: schema.EnvDefaultFunc("OS_ACCESS_TOKEN_TYPE", "access_token"),
			Description: "Which token from the OIDC response to use with Keystone: " +
				"'access_token' (default) or 'id_token' (required by OVHcloud IAM). " +
				"Can also be set with OS_ACCESS_TOKEN_TYPE.",
		},
		"oidc_username": {
			Type:        schema.TypeString,
			Optional:    true,
			DefaultFunc: schema.EnvDefaultFunc("OS_USERNAME", ""),
			Description: "End-user username for v3oidcpassword flow. " +
				"Can also be set with OS_USERNAME.",
		},
		"oidc_password": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			DefaultFunc: schema.EnvDefaultFunc("OS_PASSWORD", ""),
			Description: "End-user password for v3oidcpassword flow. " +
				"Can also be set with OS_PASSWORD.",
		},
		"authorization_code": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			DefaultFunc: schema.EnvDefaultFunc("OS_AUTHORIZATION_CODE", ""),
			Description: "Authorization code for v3oidcauthcode flow. " +
				"Can also be set with OS_AUTHORIZATION_CODE.",
		},
		"redirect_uri": {
			Type:        schema.TypeString,
			Optional:    true,
			DefaultFunc: schema.EnvDefaultFunc("OS_REDIRECT_URI", ""),
			Description: "Redirect URI registered in the IdP for v3oidcauthcode flow. " +
				"Can also be set with OS_REDIRECT_URI.",
		},
		"oidc_token": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			DefaultFunc: schema.EnvDefaultFunc("OS_ACCESS_TOKEN", ""),
			Description: "Pre-obtained OIDC token for v3oidcaccesstoken flow. " +
				"Can also be set with OS_ACCESS_TOKEN.",
		},
	}
}

// configureOIDCClient checks if the provider config specifies an OIDC auth_type,
// and if so, authenticates using gophercloud's OIDC support and returns a
// configured ProviderClient.
//
// Returns (nil, nil) if auth_type is not an OIDC type (caller falls through
// to the existing username/password/token logic).
func configureOIDCClient(ctx context.Context, d *schema.ResourceData) (*gophercloud.ProviderClient, diag.Diagnostics) {
	authType, ok := d.GetOk("auth_type")
	if !ok || authType.(string) == "" {
		// Check environment as well
		if envType := os.Getenv("OS_AUTH_TYPE"); envType != "" {
			authType = envType
		} else {
			return nil, nil // not an OIDC config, defer to standard auth
		}
	}

	authTypeStr := authType.(string)
	if !clientconfig.IsOIDCAuthType(authTypeStr) {
		return nil, nil // not OIDC — defer to standard auth
	}

	opts, diags := buildOIDCOptions(d)
	if diags.HasError() {
		return nil, diags
	}

	pc, err := clientconfig.NewOIDCProviderClient(ctx, authTypeStr, opts)
	if err != nil {
		return nil, diag.Errorf("openstack: OIDC authentication failed (%s): %v", authTypeStr, err)
	}

	return pc, nil
}

// buildOIDCOptions extracts OIDC-specific fields from the Terraform provider
// resource data and populates an OIDCOptions struct.
func buildOIDCOptions(d *schema.ResourceData) (clientconfig.OIDCOptions, diag.Diagnostics) {
	var diags diag.Diagnostics

	opts := clientconfig.OIDCOptions{
		AuthURL:           d.Get("auth_url").(string),
		IdentityProvider:  d.Get("identity_provider").(string),
		Protocol:          d.Get("protocol").(string),
		DiscoveryEndpoint: d.Get("discovery_endpoint").(string),
		TokenEndpoint:     d.Get("token_endpoint").(string),
		ClientID:          d.Get("client_id").(string),
		ClientSecret:      d.Get("client_secret").(string),
		OpenIDScope:       d.Get("openid_scope").(string),
		AccessTokenType:   d.Get("access_token_type").(string),
		ProjectID:         d.Get("tenant_id").(string),
		Username:          d.Get("oidc_username").(string),
		Password:          d.Get("oidc_password").(string),
		AuthorizationCode: d.Get("authorization_code").(string),
		RedirectURI:       d.Get("redirect_uri").(string),
		AccessToken:       d.Get("oidc_token").(string),
	}

	// Validate required common fields
	if opts.AuthURL == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "auth_url is required for OIDC authentication",
		})
	}
	if opts.IdentityProvider == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "identity_provider is required for OIDC authentication",
		})
	}
	if opts.DiscoveryEndpoint == "" && opts.TokenEndpoint == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "either discovery_endpoint or token_endpoint must be set for OIDC authentication",
		})
	}

	return opts, diags
}

// validateOIDCConfig checks for configuration issues specific to each OIDC flow
// and returns a list of error messages.
func validateOIDCConfig(authType string, opts clientconfig.OIDCOptions) error {
	if !clientconfig.IsOIDCAuthType(authType) {
		return nil
	}

	switch clientconfig.OIDCAuthType(authType) {
	case clientconfig.AuthTypeV3OIDCClientCredentials:
		if opts.ClientID == "" || opts.ClientSecret == "" {
			return fmt.Errorf("v3oidcclientcredentials requires client_id and client_secret")
		}
	case clientconfig.AuthTypeV3OIDCPassword:
		if opts.ClientID == "" || opts.ClientSecret == "" {
			return fmt.Errorf("v3oidcpassword requires client_id and client_secret")
		}
		if opts.Username == "" || opts.Password == "" {
			return fmt.Errorf("v3oidcpassword requires oidc_username and oidc_password")
		}
	case clientconfig.AuthTypeV3OIDCAuthCode:
		if opts.AuthorizationCode == "" {
			return fmt.Errorf("v3oidcauthcode requires authorization_code")
		}
	case clientconfig.AuthTypeV3OIDCAccessToken:
		if opts.AccessToken == "" {
			return fmt.Errorf("v3oidcaccesstoken requires oidc_token")
		}
	}
	return nil
}
