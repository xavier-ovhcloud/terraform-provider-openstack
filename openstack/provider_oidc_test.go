package openstack

import (
	"testing"

	clientconfig "github.com/gophercloud/utils/v2/openstack/clientconfig"
)

// ---------------------------------------------------------------------------
// validateOIDCConfig
// ---------------------------------------------------------------------------

func TestValidateOIDCConfig_ClientCredentials_Valid(t *testing.T) {
	err := validateOIDCConfig("v3oidcclientcredentials", clientconfig.OIDCOptions{
		AuthURL:           "https://ks.example.com/v3",
		IdentityProvider:  "test-idp",
		DiscoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
		ClientID:          "my-client",
		ClientSecret:      "my-secret",
		ProjectID:         "my-project",
	})
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateOIDCConfig_ClientCredentials_MissingClientID(t *testing.T) {
	err := validateOIDCConfig("v3oidcclientcredentials", clientconfig.OIDCOptions{
		AuthURL:           "https://ks.example.com/v3",
		IdentityProvider:  "test-idp",
		DiscoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
		ClientSecret:      "my-secret",
		// no ClientID
	})
	if err == nil {
		t.Error("expected error for missing client_id, got nil")
	}
}

func TestValidateOIDCConfig_Password_Valid(t *testing.T) {
	err := validateOIDCConfig("v3oidcpassword", clientconfig.OIDCOptions{
		AuthURL:          "https://ks.example.com/v3",
		IdentityProvider: "test-idp",
		TokenEndpoint:    "https://idp.example.com/token",
		ClientID:         "my-client",
		ClientSecret:     "my-secret",
		Username:         "alice",
		Password:         "s3cr3t",
	})
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateOIDCConfig_Password_MissingUsername(t *testing.T) {
	err := validateOIDCConfig("v3oidcpassword", clientconfig.OIDCOptions{
		AuthURL:          "https://ks.example.com/v3",
		IdentityProvider: "test-idp",
		TokenEndpoint:    "https://idp.example.com/token",
		ClientID:         "my-client",
		ClientSecret:     "my-secret",
		// no Username/Password
	})
	if err == nil {
		t.Error("expected error for missing username/password, got nil")
	}
}

func TestValidateOIDCConfig_AuthCode_Valid(t *testing.T) {
	err := validateOIDCConfig("v3oidcauthcode", clientconfig.OIDCOptions{
		AuthURL:           "https://ks.example.com/v3",
		IdentityProvider:  "test-idp",
		TokenEndpoint:     "https://idp.example.com/token",
		ClientID:          "my-client",
		ClientSecret:      "my-secret",
		AuthorizationCode: "auth-code-xyz",
		RedirectURI:       "https://myapp.example.com/callback",
	})
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateOIDCConfig_AuthCode_MissingCode(t *testing.T) {
	err := validateOIDCConfig("v3oidcauthcode", clientconfig.OIDCOptions{
		AuthURL:          "https://ks.example.com/v3",
		IdentityProvider: "test-idp",
		TokenEndpoint:    "https://idp.example.com/token",
		ClientID:         "my-client",
		ClientSecret:     "my-secret",
		// no AuthorizationCode
	})
	if err == nil {
		t.Error("expected error for missing authorization_code, got nil")
	}
}

func TestValidateOIDCConfig_AccessToken_Valid(t *testing.T) {
	err := validateOIDCConfig("v3oidcaccesstoken", clientconfig.OIDCOptions{
		AuthURL:          "https://ks.example.com/v3",
		IdentityProvider: "test-idp",
		AccessToken:      "my-prebuilt-token",
	})
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateOIDCConfig_AccessToken_Missing(t *testing.T) {
	err := validateOIDCConfig("v3oidcaccesstoken", clientconfig.OIDCOptions{
		AuthURL:          "https://ks.example.com/v3",
		IdentityProvider: "test-idp",
		// no AccessToken
	})
	if err == nil {
		t.Error("expected error for missing oidc_token, got nil")
	}
}

func TestValidateOIDCConfig_NonOIDCType_NoError(t *testing.T) {
	// Non-OIDC auth types should pass through validation without error
	err := validateOIDCConfig("password", clientconfig.OIDCOptions{})
	if err != nil {
		t.Errorf("expected no error for non-OIDC auth type, got: %v", err)
	}
}

func TestValidateOIDCConfig_EmptyType_NoError(t *testing.T) {
	err := validateOIDCConfig("", clientconfig.OIDCOptions{})
	if err != nil {
		t.Errorf("expected no error for empty auth_type, got: %v", err)
	}
}
