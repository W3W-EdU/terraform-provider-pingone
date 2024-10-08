package authorize

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/patrickcping/pingone-go-sdk-v2/authorize"
	"github.com/pingidentity/terraform-provider-pingone/internal/framework"
	"github.com/pingidentity/terraform-provider-pingone/internal/framework/customtypes/pingonetypes"
	"github.com/pingidentity/terraform-provider-pingone/internal/sdk"
	"github.com/pingidentity/terraform-provider-pingone/internal/verify"
)

// Types
type EditorRuleResource serviceClientType

type editorRuleResourceModel struct {
	Id            pingonetypes.ResourceIDValue `tfsdk:"id"`
	EnvironmentId pingonetypes.ResourceIDValue `tfsdk:"environment_id"`
	Name          types.String                 `tfsdk:"name"`
	Description   types.String                 `tfsdk:"description"`
	Enabled       types.Bool                   `tfsdk:"enabled"`
	// Statements     types.List                   `tfsdk:"statements"`
	Condition      types.Object `tfsdk:"condition"`
	EffectSettings types.Object `tfsdk:"effect_settings"`
	Version        types.String `tfsdk:"version"`
}

// type editorRuleStatementResourceModel struct {
// }

type editorRuleEffectSettingsResourceModel struct {
	Type types.String `tfsdk:"type"`
}

var (
	// editorRuleStatementTFObjectTypes = map[string]attr.Type{}

	editorRuleConditionTFObjectTypes = map[string]attr.Type{
		"type": types.StringType,
	}

	editorRuleEffectSettingsTFObjectTypes = map[string]attr.Type{
		"type": types.StringType,
	}
)

// Framework interfaces
var (
	_ resource.Resource                = &EditorRuleResource{}
	_ resource.ResourceWithConfigure   = &EditorRuleResource{}
	_ resource.ResourceWithImportState = &EditorRuleResource{}
)

// New Object
func NewEditorRuleResource() resource.Resource {
	return &EditorRuleResource{}
}

// Metadata
func (r *EditorRuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_authorize_editor_rule"
}

func (r *EditorRuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {

	// schema descriptions and validation settings
	const attrMinLength = 1

	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		Description: "Resource to create and manage an authorization rule for the PingOne Authorize Policy Manager in a PingOne environment.",

		Attributes: map[string]schema.Attribute{
			"id": framework.Attr_ID(),

			"environment_id": framework.Attr_LinkID(
				framework.SchemaAttributeDescriptionFromMarkdown("The ID of the environment to configure the Authorize editor rule in."),
			),

			"name": schema.StringAttribute{
				Description: framework.SchemaAttributeDescriptionFromMarkdown("").Description,
				Required:    true,

				Validators: []validator.String{
					stringvalidator.LengthAtLeast(attrMinLength),
				},
			},

			"description": schema.StringAttribute{
				Description: framework.SchemaAttributeDescriptionFromMarkdown("").Description,
				Optional:    true,
			},

			"type": schema.StringAttribute{
				Description: framework.SchemaAttributeDescriptionFromMarkdown("").Description,
				Optional:    true,
			},

			"enabled": schema.BoolAttribute{
				Description: framework.SchemaAttributeDescriptionFromMarkdown("").Description,
				Optional:    true,
			},

			// "statements": schema.ListNestedAttribute{
			// 	Description: framework.SchemaAttributeDescriptionFromMarkdown("").Description,
			// 	Optional:    true,

			// 	NestedObject: schema.NestedAttributeObject{
			// 		Attributes: map[string]schema.Attribute{},
			// 	},
			// },

			"condition": schema.SingleNestedAttribute{
				Description: framework.SchemaAttributeDescriptionFromMarkdown("").Description,
				Optional:    true,

				Attributes: dataConditionObjectSchemaAttributes(),
			},

			"effect_settings": schema.SingleNestedAttribute{
				Description: framework.SchemaAttributeDescriptionFromMarkdown("").Description,
				Required:    true,

				Attributes: dataRulesEffectSettingsObjectSchemaAttributes(),
			},

			"version": schema.StringAttribute{
				Description: framework.SchemaAttributeDescriptionFromMarkdown("").Description,
				Computed:    true,
			},
		},
	}
}

func (r *EditorRuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	resourceConfig, ok := req.ProviderData.(framework.ResourceType)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected the provider client, got: %T. Please report this issue to the provider maintainers.", req.ProviderData),
		)

		return
	}

	r.Client = resourceConfig.Client.API
	if r.Client == nil {
		resp.Diagnostics.AddError(
			"Client not initialised",
			"Expected the PingOne client, got nil.  Please report this issue to the provider maintainers.",
		)
		return
	}
}

func (r *EditorRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, state editorRuleResourceModel

	if r.Client == nil || r.Client.AuthorizeAPIClient == nil {
		resp.Diagnostics.AddError(
			"Client not initialized",
			"Expected the PingOne client, got nil.  Please report this issue to the provider maintainers.")
		return
	}

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build the model for the API
	editorRule, d := plan.expandCreate(ctx)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Run the API call
	var response *authorize.AuthorizeEditorDataRulesReferenceableRuleDTO
	resp.Diagnostics.Append(framework.ParseResponse(
		ctx,

		func() (any, *http.Response, error) {
			fO, fR, fErr := r.Client.AuthorizeAPIClient.AuthorizeEditorRulesApi.CreateRule(ctx, plan.EnvironmentId.ValueString()).AuthorizeEditorDataRulesRuleDTO(*editorRule).Execute()
			return framework.CheckEnvironmentExistsOnPermissionsError(ctx, r.Client.ManagementAPIClient, plan.EnvironmentId.ValueString(), fO, fR, fErr)
		},
		"CreateRule",
		framework.DefaultCustomError,
		sdk.DefaultCreateReadRetryable,
		&response,
	)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the state to save
	state = plan

	// Save updated data into Terraform state
	resp.Diagnostics.Append(state.toState(ctx, response)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *EditorRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data *editorRuleResourceModel

	if r.Client == nil || r.Client.AuthorizeAPIClient == nil {
		resp.Diagnostics.AddError(
			"Client not initialized",
			"Expected the PingOne client, got nil.  Please report this issue to the provider maintainers.")
		return
	}

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Run the API call
	var response *authorize.AuthorizeEditorDataRulesReferenceableRuleDTO
	resp.Diagnostics.Append(framework.ParseResponse(
		ctx,

		func() (any, *http.Response, error) {
			fO, fR, fErr := r.Client.AuthorizeAPIClient.AuthorizeEditorRulesApi.GetRule(ctx, data.EnvironmentId.ValueString(), data.Id.ValueString()).Execute()
			return framework.CheckEnvironmentExistsOnPermissionsError(ctx, r.Client.ManagementAPIClient, data.EnvironmentId.ValueString(), fO, fR, fErr)
		},
		"GetRule",
		framework.CustomErrorResourceNotFoundWarning,
		sdk.DefaultCreateReadRetryable,
		&response,
	)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Remove from state if resource is not found
	if response == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(data.toState(ctx, response)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *EditorRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state editorRuleResourceModel

	if r.Client == nil || r.Client.AuthorizeAPIClient == nil {
		resp.Diagnostics.AddError(
			"Client not initialized",
			"Expected the PingOne client, got nil.  Please report this issue to the provider maintainers.")
		return
	}

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build the model for the API
	editorRule, d := plan.expandUpdate(ctx)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Run the API call
	var response *authorize.AuthorizeEditorDataRulesReferenceableRuleDTO
	resp.Diagnostics.Append(framework.ParseResponse(
		ctx,

		func() (any, *http.Response, error) {
			fO, fR, fErr := r.Client.AuthorizeAPIClient.AuthorizeEditorRulesApi.UpdateRule(ctx, plan.EnvironmentId.ValueString(), plan.Id.ValueString()).AuthorizeEditorDataRulesReferenceableRuleDTO(*editorRule).Execute()
			return framework.CheckEnvironmentExistsOnPermissionsError(ctx, r.Client.ManagementAPIClient, plan.EnvironmentId.ValueString(), fO, fR, fErr)
		},
		"UpdateRule",
		framework.DefaultCustomError,
		nil,
		&response,
	)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the state to save
	state = plan

	// Save updated data into Terraform state
	resp.Diagnostics.Append(state.toState(ctx, response)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *EditorRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data *editorRuleResourceModel

	if r.Client == nil || r.Client.AuthorizeAPIClient == nil {
		resp.Diagnostics.AddError(
			"Client not initialized",
			"Expected the PingOne client, got nil.  Please report this issue to the provider maintainers.")
		return
	}

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Run the API call
	resp.Diagnostics.Append(framework.ParseResponse(
		ctx,

		func() (any, *http.Response, error) {
			fR, fErr := r.Client.AuthorizeAPIClient.AuthorizeEditorRulesApi.DeleteRule(ctx, data.EnvironmentId.ValueString(), data.Id.ValueString()).Execute()
			return framework.CheckEnvironmentExistsOnPermissionsError(ctx, r.Client.ManagementAPIClient, data.EnvironmentId.ValueString(), nil, fR, fErr)
		},
		"DeleteRule",
		framework.CustomErrorResourceNotFoundWarning,
		nil,
		nil,
	)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *EditorRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {

	idComponents := []framework.ImportComponent{
		{
			Label:  "environment_id",
			Regexp: verify.P1ResourceIDRegexp,
		},
		{
			Label:     "authorize_editor_rule_id",
			Regexp:    verify.P1ResourceIDRegexp,
			PrimaryID: true,
		},
	}

	attributes, err := framework.ParseImportID(req.ID, idComponents...)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			err.Error(),
		)
		return
	}

	for _, idComponent := range idComponents {
		pathKey := idComponent.Label

		if idComponent.PrimaryID {
			pathKey = "id"
		}

		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(pathKey), attributes[idComponent.Label])...)
	}
}

func (p *editorRuleResourceModel) expandCreate(ctx context.Context) (*authorize.AuthorizeEditorDataRulesRuleDTO, diag.Diagnostics) {
	var diags diag.Diagnostics

	effectSettings, d := expandEditorDataRulesEffectSettings(ctx, p.EffectSettings)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	// Main object
	data := authorize.NewAuthorizeEditorDataRulesRuleDTO(
		p.Name.ValueString(),
		*effectSettings,
	)

	if !p.Description.IsNull() && !p.Description.IsUnknown() {
		data.SetDescription(p.Description.ValueString())
	}

	if !p.Enabled.IsNull() && !p.Enabled.IsUnknown() {
		data.SetEnabled(p.Enabled.ValueBool())
	}

	// if !p.Statements.IsNull() && !p.Statements.IsUnknown() {
	// 	var plan []editorRuleStatementResourceModel
	// 	diags.Append(p.Statements.ElementsAs(ctx, &plan, false)...)
	// 	if diags.HasError() {
	// 		return nil, diags
	// 	}

	// 	statements := make([]map[string]interface{}, 0, len(plan))
	// 	for _, statementPlan := range plan {
	// 		statement := statementPlan.expand()

	// 		statements = append(statements, statement)
	// 	}

	// 	data.SetStatements(statements)
	// }

	if !p.Condition.IsNull() && !p.Condition.IsUnknown() {
		condition, d := expandEditorDataCondition(ctx, p.Condition)
		diags.Append(d...)
		if diags.HasError() {
			return nil, diags
		}

		data.SetCondition(*condition)
	}

	return data, diags
}

func (p *editorRuleResourceModel) expandUpdate(ctx context.Context) (*authorize.AuthorizeEditorDataRulesReferenceableRuleDTO, diag.Diagnostics) {
	var diags diag.Diagnostics

	dataCreate, d := p.expandCreate(ctx)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	// Use json.marshall and unmarshal to cast dataCreate to a AuthorizeEditorDataRulesReferenceableRuleDTO type
	bytes, err := json.Marshal(dataCreate)
	if err != nil {
		diags.AddError("Failed to marshal data", err.Error())
		return nil, diags
	}

	var data *authorize.AuthorizeEditorDataRulesReferenceableRuleDTO
	err = json.Unmarshal(bytes, &data)
	if err != nil {
		diags.AddError("Failed to unmarshal data", err.Error())
		return nil, diags
	}

	if !p.Version.IsNull() && !p.Version.IsUnknown() {
		data.SetVersion(p.Version.ValueString())
	}

	return data, diags
}

func (p *editorRuleResourceModel) toState(ctx context.Context, apiObject *authorize.AuthorizeEditorDataRulesReferenceableRuleDTO) diag.Diagnostics {
	var diags, d diag.Diagnostics

	if apiObject == nil {
		diags.AddError(
			"Data object missing",
			"Cannot convert the data object to state as the data object is nil.  Please report this to the provider maintainers.",
		)
		return diags
	}

	p.Id = framework.PingOneResourceIDOkToTF(apiObject.GetIdOk())
	p.EnvironmentId = framework.PingOneResourceIDToTF(*apiObject.GetEnvironment().Id)
	p.Name = framework.StringOkToTF(apiObject.GetNameOk())
	// p.Type = framework.EnumOkToTF(apiObject.GetTypeOk())
	p.Description = framework.StringOkToTF(apiObject.GetDescriptionOk())
	p.Enabled = framework.BoolOkToTF(apiObject.GetEnabledOk())

	// p.Statements, d = editorRuleStatementsOkToTF(apiObject.GetStatementsOk())
	// diags.Append(d...)

	conditionVal, ok := apiObject.GetConditionOk()
	p.Condition, d = editorDataConditionOkToTF(ctx, conditionVal, ok)
	diags.Append(d...)

	effectSettingsVal, ok := apiObject.GetEffectSettingsOk()
	p.EffectSettings, d = editorDataRulesEffectSettingsOkToTF(ctx, effectSettingsVal, ok)
	diags.Append(d...)

	return diags
}
