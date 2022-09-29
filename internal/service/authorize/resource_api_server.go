package authorize

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/patrickcping/pingone-go-sdk-v2/authorize"
	client "github.com/pingidentity/terraform-provider-pingone/internal/client"
	"github.com/pingidentity/terraform-provider-pingone/internal/sdk"
	"github.com/pingidentity/terraform-provider-pingone/internal/verify"
)

func ResourceAPIServer() *schema.Resource {
	return &schema.Resource{

		// This description is used by the documentation generator and the language server.
		Description: "Resource to create and manage PingOne Authorize API Servers.",

		CreateContext: resourceAPIServerCreate,
		ReadContext:   resourceAPIServerRead,
		UpdateContext: resourceAPIServerUpdate,
		DeleteContext: resourceAPIServerDelete,

		Importer: &schema.ResourceImporter{
			StateContext: resourceAPIServerImport,
		},

		Schema: map[string]*schema.Schema{
			"environment_id": {
				Description:      "The ID of the environment to create the group in.",
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validation.ToDiagFunc(verify.ValidP1ResourceID),
				ForceNew:         true,
			},
			"name": {
				Description:      "A string that specifies the API server resource name. The name value must be unique among all API servers, and it must be a valid resource name.",
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"authorization_server_resource_id": {
				Description:      "The ID of the custom PingOne resource, that defines the characteristics of the OAuth 2.0 access tokens used to get access to the APIs on the API server such as the audience and scopes. This property must identify a PingOne resource with a `type` property value of `CUSTOM`.",
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"base_url_list": {
				Description: "An array of string that specifies the possible base URLs that an end-user will use to access the APIs hosted on the customer's API server. Multiple base URLs may be specified to support cases where the same API may be available from multiple URLs (for example, from a user-friendly domain URL and an internal domain URL). Base URLs must be valid absolute URLs with the https or http scheme. If the path component is non-empty, it must not end in a trailing slash. The path must not contain empty backslash, dot, or double-dot segments. It must not have a query or fragment present, and the host portion of the authority must be a DNS hostname or valid IP (IPv4 or IPv6). The length must be less than or equal to 256 characters.",
				Type:        schema.TypeSet,
				Required:    true,
				MinItems:    1,
				Elem: &schema.Schema{
					Type:             schema.TypeString,
					ValidateDiagFunc: validation.ToDiagFunc(validation.String),
				},
			},
			"operation": {
				Description: "A block that describes an individual operation configuration.  Operations define HTTP method and path combinations, which combine with the configured Base URLs to match client requests.",
				Type:        schema.TypeSet,
				Required:    true,
				MinItems:    1,
				MaxItems:    25,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Description:      "A string that specifies the name of the operation.",
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
						},
						"methods": {
							Description: "A list that specifies the methods that define the operation. No duplicates are allowed. Each element must be a valid HTTP token, according to [RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230), and cannot exceed 64 characters. An empty list is not valid. To indicate that an operation is defined for every method, the methods list should not be defined. The `methods` list is limited to 10 entries.",
							Type:        schema.TypeSet,
							Optional:    true,
							MaxItems:    10,
							Elem: &schema.Schema{
								Type:             schema.TypeString,
								ValidateDiagFunc: validation.ToDiagFunc(validation.String),
							},
						},
						"path": {
							Description: "A block that specifies details of a path that defines the operation. The same literal pattern is not allowed within the same operation (the pattern of a `path` element must be unique as compared to all other patterns in the same `path` list). However, the same literal pattern is allowed in different operations (for example, `OperationA`, `/path1`, `OperationB`, `/path1` is valid). The paths array is limited to 10 entries.",
							Type:        schema.TypeSet,
							Required:    true,
							MinItems:    1,
							MaxItems:    10,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"pattern": {
										Description:      "A string that specifies the pattern used to identify the path or paths for the operation. The semantics of the pattern are determined by the type. For any type, the pattern can contain characters that are otherwise invalid in a URL path. Invalid characters are handled by performing matching against a percent-decoded HTTP request target path. This allows an administrator to configure patterns without worrying about percent encoding special characters. When the `type` is `PARAMETER`, the syntax outlined in the table below is enforced. Additionally, the pattern must contain a wildcard, double wildcard or parameter capture. When the type is `EXACT`, the pattern can be any byte sequence except for ASCII control characters such as line feeds or carriage returns. The length of the pattern cannot exceed 2048 characters. The path pattern must not contain empty path segments such as `/../`, `//`, and `/./`.",
										Type:             schema.TypeString,
										Required:         true,
										ValidateDiagFunc: validation.ToDiagFunc(validation.StringLenBetween(1, 2048)),
									},
									"type": {
										Description:      fmt.Sprintf("A string that specifies the type of the pattern. Options are `%s` ( the verbatim pattern is compared against the path from the request using a case-sensitive comparison) and `%s` (the pattern is compared against the path from the request using a case-sensitive comparison, using the syntax below to encode wildcards and path segment captures.)", string(authorize.ENUMAPISERVERPATTERNTYPE_EXACT), string(authorize.ENUMAPISERVERPATTERNTYPE_PARAMETER)),
										Type:             schema.TypeString,
										Required:         true,
										ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{string(authorize.ENUMAPISERVERPATTERNTYPE_EXACT), string(authorize.ENUMAPISERVERPATTERNTYPE_PARAMETER)}, false)),
									},
								},
							},
						},
						"access_control_group_options": {
							Description: "Group access control settings.",
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"group_ids": {
										Description: "A set that specifies the list of group IDs that define the access requirements for the operation. The end user must be a member of one or more of these groups to gain access to the operation. This is a required property if `operations.value.accessControl.group` is set. The ID must reference a group that exists at the time the data is persisted. There is no referential integrity between a group and this configuration. If a group is subsequently deleted, the access control configuration will continue to reference that group.",
										Type:        schema.TypeSet,
										MaxItems:    25,
										Elem: &schema.Schema{
											Type:             schema.TypeString,
											ValidateDiagFunc: validation.ToDiagFunc(verify.ValidP1ResourceID),
										},
										Required: true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func resourceAPIServerCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	p1Client := meta.(*client.Client)
	apiClient := p1Client.API.AuthorizeAPIClient
	ctx = context.WithValue(ctx, authorize.ContextServerVariables, map[string]string{
		"suffix": p1Client.API.Region.URLSuffix,
	})
	var diags diag.Diagnostics

	apiServer := expandAPIServer(d)

	resp, diags := sdk.ParseResponse(
		ctx,

		func() (interface{}, *http.Response, error) {
			return apiClient.APIServersApi.CreateAPIServer(ctx, d.Get("environment_id").(string)).APIServer(*apiServer).Execute()
		},
		"CreateAPIServer",
		sdk.DefaultCustomError,
		sdk.DefaultCreateReadRetryable,
	)
	if diags.HasError() {
		return diags
	}

	respObject := resp.(*authorize.APIServer)

	d.SetId(respObject.GetId())

	return resourceAPIServerRead(ctx, d, meta)
}

func resourceAPIServerRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	p1Client := meta.(*client.Client)
	apiClient := p1Client.API.AuthorizeAPIClient
	ctx = context.WithValue(ctx, authorize.ContextServerVariables, map[string]string{
		"suffix": p1Client.API.Region.URLSuffix,
	})
	var diags diag.Diagnostics

	resp, diags := sdk.ParseResponse(
		ctx,

		func() (interface{}, *http.Response, error) {
			return apiClient.APIServersApi.ReadOneAPIServer(ctx, d.Get("environment_id").(string), d.Id()).Execute()
		},
		"ReadOneAPIServer",
		sdk.CustomErrorResourceNotFoundWarning,
		sdk.DefaultCreateReadRetryable,
	)
	if diags.HasError() {
		return diags
	}

	if resp == nil {
		d.SetId("")
		return nil
	}

	respObject := resp.(*authorize.APIServer)

	d.Set("name", respObject.GetName())
	d.Set("authorization_server_resource_id", respObject.GetAuthorizationServer().Resource.Id)
	d.Set("base_url_list", respObject.GetBaseURLs())
	d.Set("operation", flattenAPIServerOperations(respObject.GetOperations()))

	return diags
}

func resourceAPIServerUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	p1Client := meta.(*client.Client)
	apiClient := p1Client.API.AuthorizeAPIClient
	ctx = context.WithValue(ctx, authorize.ContextServerVariables, map[string]string{
		"suffix": p1Client.API.Region.URLSuffix,
	})
	var diags diag.Diagnostics

	apiServer := expandAPIServer(d)

	_, diags = sdk.ParseResponse(
		ctx,

		func() (interface{}, *http.Response, error) {
			return apiClient.APIServersApi.UpdateAPIServer(ctx, d.Get("environment_id").(string), d.Id()).APIServer(*apiServer).Execute()
		},
		"UpdateAPIServer",
		sdk.DefaultCustomError,
		sdk.DefaultRetryable,
	)
	if diags.HasError() {
		return diags
	}

	return resourceAPIServerRead(ctx, d, meta)
}

func resourceAPIServerDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	p1Client := meta.(*client.Client)
	apiClient := p1Client.API.AuthorizeAPIClient
	ctx = context.WithValue(ctx, authorize.ContextServerVariables, map[string]string{
		"suffix": p1Client.API.Region.URLSuffix,
	})
	var diags diag.Diagnostics

	_, diags = sdk.ParseResponse(
		ctx,

		func() (interface{}, *http.Response, error) {
			r, err := apiClient.APIServersApi.DeleteAPIServer(ctx, d.Get("environment_id").(string), d.Id()).Execute()
			return nil, r, err
		},
		"DeleteAPIServer",
		sdk.CustomErrorResourceNotFoundWarning,
		sdk.DefaultRetryable,
	)
	if diags.HasError() {
		return diags
	}

	return diags
}

func resourceAPIServerImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	splitLength := 2
	attributes := strings.SplitN(d.Id(), "/", splitLength)

	if len(attributes) != splitLength {
		return nil, fmt.Errorf("invalid id (\"%s\") specified, should be in format \"environmentID/apiServerID\"", d.Id())
	}

	environmentID, apiServerID := attributes[0], attributes[1]

	d.Set("environment_id", environmentID)
	d.SetId(apiServerID)

	resourceAPIServerRead(ctx, d, meta)

	return []*schema.ResourceData{d}, nil
}

func expandAPIServer(d *schema.ResourceData) *authorize.APIServer {

	authorizationServer := *authorize.NewAPIServerAuthorizationServer(*authorize.NewAPIServerAuthorizationServerResource(d.Get("authorization_server_resource_id").(string)))

	baseURLs := make([]string, 0)
	for _, v := range d.Get("base_url_list").(*schema.Set).List() {
		baseURLs = append(baseURLs, v.(string))
	}

	apiServer := authorize.NewAPIServer(authorizationServer, baseURLs, d.Get("name").(string)) // APIServer |  (optional)

	return apiServer

}

func flattenAPIServerOperations(c map[string]interface{}) []map[string]interface{} {

	operations := make([]map[string]interface{}, 0)

	for key, element := range c {
		fmt.Println("Key:", key, "=>", "Element:", element)
	}

	return operations
}
