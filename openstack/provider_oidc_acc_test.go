// Acceptance tests for OIDC authentication in the Terraform OpenStack provider.
//
// These tests require a live environment. Set the following env vars:
//
//	TF_ACC=1
//	OS_AUTH_URL=https://auth.cloud.ovh.net/v3
//	OS_AUTH_TYPE=v3oidcclientcredentials
//	OS_IDENTITY_PROVIDER=ovhcloud-emea
//	OS_DISCOVERY_ENDPOINT=https://iam.ovh.net/role-adapter/urn:v1:eu:resource:publicCloudProject:pci/.well-known/openid-configuration
//	OS_CLIENT_ID=<your_service_account_client_id>
//	OS_CLIENT_SECRET=<your_service_account_secret>
//	OS_ACCESS_TOKEN_TYPE=id_token
//	OS_OPENID_SCOPE=openid profile email publicCloudProject/all
//	OS_PROJECT_ID=<your_project_id>
//	OS_REGION_NAME=GRA11
package openstack

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// TestAccOIDCClientCredentials_basic verifies that Terraform can authenticate
// via OVHcloud IAM using v3oidcclientcredentials and create a real resource.
func TestAccOIDCClientCredentials_basic(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set — skipping acceptance test")
	}
	if os.Getenv("OS_AUTH_TYPE") != "v3oidcclientcredentials" {
		t.Skip("OS_AUTH_TYPE != v3oidcclientcredentials — skipping OIDC acceptance test")
	}

	sgName := fmt.Sprintf("tf-oidc-test-%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlpha))

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccOIDCClientCredentialsConfig(sgName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("openstack_networking_secgroup_v2.test", "name", sgName),
					resource.TestCheckResourceAttrSet("openstack_networking_secgroup_v2.test", "id"),
				),
			},
		},
	})
}

func testAccOIDCClientCredentialsConfig(sgName string) string {
	return fmt.Sprintf(`
provider "openstack" {
  auth_url           = "%s"
  auth_type          = "v3oidcclientcredentials"
  identity_provider  = "%s"
  protocol           = "openid"
  discovery_endpoint = "%s"
  client_id          = "%s"
  client_secret      = "%s"
  openid_scope       = "%s"
  access_token_type  = "%s"
  tenant_id          = "%s"
  region             = "%s"
}

resource "openstack_networking_secgroup_v2" "test" {
  name        = %q
  description = "Created by OIDC acceptance test"
}
`,
		os.Getenv("OS_AUTH_URL"),
		os.Getenv("OS_IDENTITY_PROVIDER"),
		os.Getenv("OS_DISCOVERY_ENDPOINT"),
		os.Getenv("OS_CLIENT_ID"),
		os.Getenv("OS_CLIENT_SECRET"),
		os.Getenv("OS_OPENID_SCOPE"),
		os.Getenv("OS_ACCESS_TOKEN_TYPE"),
		os.Getenv("OS_PROJECT_ID"),
		os.Getenv("OS_REGION_NAME"),
		sgName,
	)
}

// TestAccOIDCAccessToken_basic verifies v3oidcaccesstoken with a pre-obtained token.
func TestAccOIDCAccessToken_basic(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set — skipping acceptance test")
	}
	if os.Getenv("OS_ACCESS_TOKEN") == "" {
		t.Skip("OS_ACCESS_TOKEN not set — skipping v3oidcaccesstoken acceptance test")
	}

	sgName := fmt.Sprintf("tf-oidc-at-test-%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlpha))

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccOIDCAccessTokenConfig(sgName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("openstack_networking_secgroup_v2.test", "name", sgName),
				),
			},
		},
	})
}

func testAccOIDCAccessTokenConfig(sgName string) string {
	return fmt.Sprintf(`
provider "openstack" {
  auth_url          = "%s"
  auth_type         = "v3oidcaccesstoken"
  identity_provider = "%s"
  protocol          = "openid"
  oidc_token        = "%s"
  tenant_id         = "%s"
  region            = "%s"
}

resource "openstack_networking_secgroup_v2" "test" {
  name        = %q
  description = "Created by OIDC access token acceptance test"
}
`,
		os.Getenv("OS_AUTH_URL"),
		os.Getenv("OS_IDENTITY_PROVIDER"),
		os.Getenv("OS_ACCESS_TOKEN"),
		os.Getenv("OS_PROJECT_ID"),
		os.Getenv("OS_REGION_NAME"),
		sgName,
	)
}
