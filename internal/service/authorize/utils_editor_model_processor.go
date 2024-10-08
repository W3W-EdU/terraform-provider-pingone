package authorize

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/patrickcping/pingone-go-sdk-v2/authorize"
	"github.com/pingidentity/terraform-provider-pingone/internal/framework"
	listvalidatorinternal "github.com/pingidentity/terraform-provider-pingone/internal/framework/listvalidator"
	objectvalidatorinternal "github.com/pingidentity/terraform-provider-pingone/internal/framework/objectvalidator"
	stringvalidatorinternal "github.com/pingidentity/terraform-provider-pingone/internal/framework/stringvalidator"
	"github.com/pingidentity/terraform-provider-pingone/internal/utils"
)

const processorNestedIterationMaxDepth = 2

func dataProcessorObjectSchemaAttributes() (attributes map[string]schema.Attribute) {
	const initialIteration = 1
	return dataProcessorObjectSchemaAttributesIteration(initialIteration)
}
func dataProcessorObjectSchemaAttributesIteration(iteration int32) (attributes map[string]schema.Attribute) {

	supportedProcessorTypes := authorize.AllowedEnumAuthorizeEditorDataProcessorDTOTypeEnumValues

	if iteration >= processorNestedIterationMaxDepth {

		newSupportedTypes := []authorize.EnumAuthorizeEditorDataProcessorDTOType{
			"JSON_PATH",
			"REFERENCE",
			"SPEL",
			"XPATH",
		}

		supportedProcessorTypes = newSupportedTypes
	}

	typeDescription := framework.SchemaAttributeDescriptionFromMarkdown(
		"A string that specifies the processor type.",
	).AllowedValuesEnum(supportedProcessorTypes)

	processorsDescription := framework.SchemaAttributeDescriptionFromMarkdown(
		"The list of processors to apply in the given order.",
	).AppendMarkdownString(fmt.Sprintf("This field is required when `type` is `%s`.", string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_CHAIN)))

	predicateDescription := framework.SchemaAttributeDescriptionFromMarkdown(
		"",
	).AppendMarkdownString(fmt.Sprintf("This field is required when `type` is `%s`.", string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_COLLECTION_FILTER)))

	processorDescription := framework.SchemaAttributeDescriptionFromMarkdown(
		"",
	).AppendMarkdownString(fmt.Sprintf("This field is required when `type` is `%s`.", string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_COLLECTION_TRANSFORM)))

	expressionDescription := framework.SchemaAttributeDescriptionFromMarkdown(
		fmt.Sprintf("A string that specifies the expression to use. If the `type` is `%s`, the expression should be a valid JSON path expression, if the `type` is `%s`, the expression should be a valid SpEL expression and if the `type` is `%s`, the expression should be a valid XPath expression.", string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_JSON_PATH), string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_SPEL), string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_XPATH)),
	).AppendMarkdownString(fmt.Sprintf("This field is required when `type` is `%s`, `%s` or `%s`.", string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_JSON_PATH), string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_SPEL), string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_XPATH)))

	valueTypeDescription := framework.SchemaAttributeDescriptionFromMarkdown(
		"An object that specifies the output type of the value.",
	).AppendMarkdownString(fmt.Sprintf("This field is required when `type` is `%s`, `%s` or `%s`.", string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_JSON_PATH), string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_SPEL), string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_XPATH)))

	processorRefDescription := framework.SchemaAttributeDescriptionFromMarkdown(
		"An object that specifies configuration settings for the authorization processor to reference.",
	).AppendMarkdownString(fmt.Sprintf("This field is required when `type` is `%s`.", string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_REFERENCE)))

	attributes = map[string]schema.Attribute{
		"name": schema.StringAttribute{
			Description: framework.SchemaAttributeDescriptionFromMarkdown("A user-friendly authorization processor name. The value must be unique.").Description,
			Required:    true,
		},

		"type": schema.StringAttribute{
			Description:         typeDescription.Description,
			MarkdownDescription: typeDescription.MarkdownDescription,
			Required:            true,

			Validators: []validator.String{
				stringvalidator.OneOf(utils.EnumSliceToStringSlice(supportedProcessorTypes)...),
			},
		},
	}

	// type == "CHAIN"
	if slices.Contains(supportedProcessorTypes, authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_CHAIN) {
		attributes["processors"] = schema.ListNestedAttribute{
			Description:         processorsDescription.Description,
			MarkdownDescription: processorsDescription.MarkdownDescription,
			Optional:            true,

			Validators: []validator.List{
				listvalidatorinternal.IsRequiredIfMatchesPathValue(
					types.StringValue(string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_CHAIN)),
					path.MatchRelative().AtParent().AtName("type"),
				),
			},

			NestedObject: schema.NestedAttributeObject{
				Attributes: dataProcessorObjectSchemaAttributesIteration(iteration + 1),
			},
		}
	}

	// type == "COLLECTION_FILTER"
	if slices.Contains(supportedProcessorTypes, authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_COLLECTION_FILTER) {
		attributes["predicate"] = schema.SingleNestedAttribute{
			Description:         predicateDescription.Description,
			MarkdownDescription: predicateDescription.MarkdownDescription,
			Optional:            true,

			Validators: []validator.Object{
				objectvalidatorinternal.IsRequiredIfMatchesPathValue(
					types.StringValue(string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_COLLECTION_FILTER)),
					path.MatchRelative().AtParent().AtName("type"),
				),
			},

			Attributes: dataProcessorObjectSchemaAttributesIteration(iteration + 1),
		}
	}

	// type == "COLLECTION_TRANSFORM"
	if slices.Contains(supportedProcessorTypes, authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_COLLECTION_TRANSFORM) {
		attributes["processor"] = schema.SingleNestedAttribute{
			Description:         processorDescription.Description,
			MarkdownDescription: processorDescription.MarkdownDescription,
			Optional:            true,

			Validators: []validator.Object{
				objectvalidatorinternal.IsRequiredIfMatchesPathValue(
					types.StringValue(string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_COLLECTION_TRANSFORM)),
					path.MatchRelative().AtParent().AtName("type"),
				),
			},

			Attributes: dataProcessorObjectSchemaAttributesIteration(iteration + 1),
		}
	}

	// type == "JSON_PATH", type == "SPEL", type == "XPATH"
	if slices.Contains(supportedProcessorTypes, authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_JSON_PATH) ||
		slices.Contains(supportedProcessorTypes, authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_SPEL) ||
		slices.Contains(supportedProcessorTypes, authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_XPATH) {
		attributes["expression"] = schema.StringAttribute{
			Description:         expressionDescription.Description,
			MarkdownDescription: expressionDescription.MarkdownDescription,
			Optional:            true,

			Validators: []validator.String{
				stringvalidatorinternal.IsRequiredIfMatchesPathValue(
					types.StringValue(string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_JSON_PATH)),
					path.MatchRelative().AtParent().AtName("type"),
				),
				stringvalidatorinternal.IsRequiredIfMatchesPathValue(
					types.StringValue(string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_SPEL)),
					path.MatchRelative().AtParent().AtName("type"),
				),
				stringvalidatorinternal.IsRequiredIfMatchesPathValue(
					types.StringValue(string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_XPATH)),
					path.MatchRelative().AtParent().AtName("type"),
				),
			},
		}

		attributes["value_type"] = schema.SingleNestedAttribute{
			Description:         valueTypeDescription.Description,
			MarkdownDescription: valueTypeDescription.MarkdownDescription,
			Optional:            true,

			Validators: []validator.Object{
				objectvalidatorinternal.IsRequiredIfMatchesPathValue(
					types.StringValue(string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_JSON_PATH)),
					path.MatchRelative().AtParent().AtName("type"),
				),
				objectvalidatorinternal.IsRequiredIfMatchesPathValue(
					types.StringValue(string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_SPEL)),
					path.MatchRelative().AtParent().AtName("type"),
				),
				objectvalidatorinternal.IsRequiredIfMatchesPathValue(
					types.StringValue(string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_XPATH)),
					path.MatchRelative().AtParent().AtName("type"),
				),
			},

			Attributes: valueTypeObjectSchemaAttributes(),
		}
	}

	// type == "REFERENCE"
	if slices.Contains(supportedProcessorTypes, authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_REFERENCE) {
		attributes["processor_ref"] = schema.SingleNestedAttribute{
			Description:         processorRefDescription.Description,
			MarkdownDescription: processorRefDescription.MarkdownDescription,
			Optional:            true,

			Validators: []validator.Object{
				objectvalidatorinternal.IsRequiredIfMatchesPathValue(
					types.StringValue(string(authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_REFERENCE)),
					path.MatchRelative().AtParent().AtName("type"),
				),
			},

			Attributes: referenceIdObjectSchemaAttributes(framework.SchemaAttributeDescriptionFromMarkdown("A string that specifies the ID of the authorization processor in the trust framework.")),
		}
	}

	return attributes
}

type editorDataProcessorResourceModel struct {
	Name         types.String `tfsdk:"name"`
	Type         types.String `tfsdk:"type"`
	Processors   types.List   `tfsdk:"processors"`
	Predicate    types.Object `tfsdk:"predicate"`
	Processor    types.Object `tfsdk:"processor"`
	Expression   types.String `tfsdk:"expression"`
	ValueType    types.Object `tfsdk:"value_type"`
	ProcessorRef types.Object `tfsdk:"processor_ref"`
}

var editorDataProcessorTFObjectTypes = initializeEditorDataProcessorTFObjectTypes()

func initializeEditorDataProcessorTFObjectTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"name": types.StringType,
		"type": types.StringType,
		"processors": types.ListType{
			ElemType: types.ObjectType{AttrTypes: nil}, // Temporarily set to nil
		},
		"predicate":     types.ObjectType{AttrTypes: nil}, // Temporarily set to nil
		"processor":     types.ObjectType{AttrTypes: nil}, // Temporarily set to nil
		"expression":    types.StringType,
		"value_type":    types.ObjectType{AttrTypes: editorValueTypeTFObjectTypes},
		"processor_ref": types.ObjectType{AttrTypes: editorReferenceObjectTFObjectTypes},
	}
}

func init() {
	// Now set the correct AttrTypes to break the initialization cycle
	editorDataProcessorTFObjectTypes["processors"] = types.ListType{
		ElemType: types.ObjectType{AttrTypes: editorDataProcessorTFObjectTypes},
	}
	editorDataProcessorTFObjectTypes["predicate"] = types.ObjectType{AttrTypes: editorDataProcessorTFObjectTypes}
	editorDataProcessorTFObjectTypes["processor"] = types.ObjectType{AttrTypes: editorDataProcessorTFObjectTypes}
}

func expandEditorDataProcessor(ctx context.Context, processor basetypes.ObjectValue) (processorObject *authorize.AuthorizeEditorDataProcessorDTO, diags diag.Diagnostics) {
	var plan *editorDataProcessorResourceModel
	diags.Append(processor.As(ctx, &plan, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    false,
		UnhandledUnknownAsEmpty: false,
	})...)
	if diags.HasError() {
		return
	}

	processorObject, d := plan.expand(ctx)
	diags.Append(d...)
	if diags.HasError() {
		return
	}

	return
}

func (p *editorDataProcessorResourceModel) expand(ctx context.Context) (*authorize.AuthorizeEditorDataProcessorDTO, diag.Diagnostics) {
	var diags, d diag.Diagnostics

	data := authorize.AuthorizeEditorDataProcessorDTO{}

	switch authorize.EnumAuthorizeEditorDataProcessorDTOType(p.Type.ValueString()) {
	case authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_CHAIN:
		data.AuthorizeEditorDataProcessorsChainProcessorDTO, d = p.expandChainProcessor(ctx)
		diags.Append(d...)
	case authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_COLLECTION_FILTER:
		data.AuthorizeEditorDataProcessorsCollectionFilterProcessorDTO, d = p.expandCollectionFilterProcessor(ctx)
		diags.Append(d...)
	case authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_COLLECTION_TRANSFORM:
		data.AuthorizeEditorDataProcessorsCollectionTransformProcessorDTO, d = p.expandCollectionTransformProcessor(ctx)
		diags.Append(d...)
	case authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_JSON_PATH:
		data.AuthorizeEditorDataProcessorsJsonPathProcessorDTO, d = p.expandJsonPathProcessor(ctx)
		diags.Append(d...)
	case authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_REFERENCE:
		data.AuthorizeEditorDataProcessorsReferenceProcessorDTO, d = p.expandReferenceProcessor(ctx)
		diags.Append(d...)
	case authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_SPEL:
		data.AuthorizeEditorDataProcessorsSpelProcessorDTO, d = p.expandSPELProcessor(ctx)
		diags.Append(d...)
	case authorize.ENUMAUTHORIZEEDITORDATAPROCESSORDTOTYPE_XPATH:
		data.AuthorizeEditorDataProcessorsXPathProcessorDTO, d = p.expandXPATHProcessor(ctx)
		diags.Append(d...)
	default:
		diags.AddError(
			"Invalid processor type",
			fmt.Sprintf("The processor type '%s' is not supported.  Please raise an issue with the provider maintainers.", p.Type.ValueString()),
		)
	}

	if diags.HasError() {
		return nil, diags
	}

	return &data, diags
}

func (p *editorDataProcessorResourceModel) expandChainProcessor(ctx context.Context) (*authorize.AuthorizeEditorDataProcessorsChainProcessorDTO, diag.Diagnostics) {
	var diags diag.Diagnostics

	var plan []editorDataProcessorResourceModel
	diags.Append(p.Processors.ElementsAs(ctx, &plan, false)...)
	if diags.HasError() {
		return nil, diags
	}

	processors := make([]authorize.AuthorizeEditorDataProcessorDTO, 0, len(plan))
	for _, processorPlan := range plan {

		processorObject, d := processorPlan.expand(ctx)
		diags.Append(d...)
		if diags.HasError() {
			return nil, diags
		}

		processors = append(processors, *processorObject)
	}

	data := authorize.NewAuthorizeEditorDataProcessorsChainProcessorDTO(
		p.Name.ValueString(),
		authorize.EnumAuthorizeEditorDataProcessorDTOType(p.Type.ValueString()),
		processors,
	)

	return data, diags
}

func (p *editorDataProcessorResourceModel) expandCollectionFilterProcessor(ctx context.Context) (*authorize.AuthorizeEditorDataProcessorsCollectionFilterProcessorDTO, diag.Diagnostics) {
	var diags diag.Diagnostics

	predicate, d := expandEditorDataProcessor(ctx, p.Processor)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	data := authorize.NewAuthorizeEditorDataProcessorsCollectionFilterProcessorDTO(
		p.Name.ValueString(),
		authorize.EnumAuthorizeEditorDataProcessorDTOType(p.Type.ValueString()),
		*predicate,
	)

	return data, diags
}

func (p *editorDataProcessorResourceModel) expandCollectionTransformProcessor(ctx context.Context) (*authorize.AuthorizeEditorDataProcessorsCollectionTransformProcessorDTO, diag.Diagnostics) {
	var diags diag.Diagnostics

	processor, d := expandEditorDataProcessor(ctx, p.Processor)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	data := authorize.NewAuthorizeEditorDataProcessorsCollectionTransformProcessorDTO(
		p.Name.ValueString(),
		authorize.EnumAuthorizeEditorDataProcessorDTOType(p.Type.ValueString()),
		*processor,
	)

	return data, diags
}

func (p *editorDataProcessorResourceModel) expandJsonPathProcessor(ctx context.Context) (*authorize.AuthorizeEditorDataProcessorsJsonPathProcessorDTO, diag.Diagnostics) {
	var diags diag.Diagnostics

	valueType, d := expandEditorValueType(ctx, p.ValueType)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	data := authorize.NewAuthorizeEditorDataProcessorsJsonPathProcessorDTO(
		p.Name.ValueString(),
		authorize.EnumAuthorizeEditorDataProcessorDTOType(p.Type.ValueString()),
		p.Expression.ValueString(),
		*valueType,
	)

	return data, diags
}

func (p *editorDataProcessorResourceModel) expandReferenceProcessor(ctx context.Context) (*authorize.AuthorizeEditorDataProcessorsReferenceProcessorDTO, diag.Diagnostics) {
	var diags diag.Diagnostics

	processorRef, d := expandEditorReferenceData(ctx, p.ProcessorRef)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	data := authorize.NewAuthorizeEditorDataProcessorsReferenceProcessorDTO(
		p.Name.ValueString(),
		authorize.EnumAuthorizeEditorDataProcessorDTOType(p.Type.ValueString()),
		*processorRef,
	)

	return data, diags
}

func (p *editorDataProcessorResourceModel) expandSPELProcessor(ctx context.Context) (*authorize.AuthorizeEditorDataProcessorsSpelProcessorDTO, diag.Diagnostics) {
	var diags diag.Diagnostics

	valueType, d := expandEditorValueType(ctx, p.ValueType)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	data := authorize.NewAuthorizeEditorDataProcessorsSpelProcessorDTO(
		p.Name.ValueString(),
		authorize.EnumAuthorizeEditorDataProcessorDTOType(p.Type.ValueString()),
		p.Expression.ValueString(),
		*valueType,
	)

	return data, diags
}

func (p *editorDataProcessorResourceModel) expandXPATHProcessor(ctx context.Context) (*authorize.AuthorizeEditorDataProcessorsXPathProcessorDTO, diag.Diagnostics) {
	var diags diag.Diagnostics

	valueType, d := expandEditorValueType(ctx, p.ValueType)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	data := authorize.NewAuthorizeEditorDataProcessorsXPathProcessorDTO(
		p.Name.ValueString(),
		authorize.EnumAuthorizeEditorDataProcessorDTOType(p.Type.ValueString()),
		p.Expression.ValueString(),
		*valueType,
	)

	return data, diags
}

func editorDataProcessorOkToTF(ctx context.Context, apiObject *authorize.AuthorizeEditorDataProcessorDTO, ok bool) (basetypes.ObjectValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	if !ok || apiObject == nil || cmp.Equal(apiObject, &authorize.AuthorizeEditorDataProcessorDTO{}) {
		return types.ObjectNull(editorDataProcessorTFObjectTypes), diags
	}

	attributeMap := map[string]attr.Value{}

	switch t := apiObject.GetActualInstance().(type) {
	case authorize.AuthorizeEditorDataProcessorsChainProcessorDTO:

		attributeMap = map[string]attr.Value{
			"name":       framework.StringOkToTF(t.GetNameOk()),
			"type":       framework.EnumOkToTF(t.GetTypeOk()),
			"processors": nil,
		}

	case authorize.AuthorizeEditorDataProcessorsCollectionFilterProcessorDTO:

		predicateResp, ok := t.GetPredicateOk()
		predicate, d := editorDataProcessorOkToTF(ctx, predicateResp, ok)
		diags.Append(d...)

		attributeMap = map[string]attr.Value{
			"name":      framework.StringOkToTF(t.GetNameOk()),
			"type":      framework.EnumOkToTF(t.GetTypeOk()),
			"predicate": predicate,
		}

	case authorize.AuthorizeEditorDataProcessorsCollectionTransformProcessorDTO:

		processorResp, ok := t.GetProcessorOk()
		processor, d := editorDataProcessorOkToTF(ctx, processorResp, ok)
		diags.Append(d...)

		attributeMap = map[string]attr.Value{
			"name":      framework.StringOkToTF(t.GetNameOk()),
			"type":      framework.EnumOkToTF(t.GetTypeOk()),
			"processor": processor,
		}

	case authorize.AuthorizeEditorDataProcessorsJsonPathProcessorDTO:

		valueType, d := editorValueTypeOkToTF(t.GetValueTypeOk())
		diags.Append(d...)

		attributeMap = map[string]attr.Value{
			"name":       framework.StringOkToTF(t.GetNameOk()),
			"type":       framework.EnumOkToTF(t.GetTypeOk()),
			"expression": framework.StringOkToTF(t.GetNameOk()),
			"value_type": valueType,
		}

	case authorize.AuthorizeEditorDataProcessorsReferenceProcessorDTO:

		processorRef, d := editorDataReferenceObjectOkToTF(t.GetProcessorOk())
		diags.Append(d...)

		attributeMap = map[string]attr.Value{
			"name":          framework.StringOkToTF(t.GetNameOk()),
			"type":          framework.EnumOkToTF(t.GetTypeOk()),
			"processor_ref": processorRef,
		}

	case authorize.AuthorizeEditorDataProcessorsSpelProcessorDTO:

		valueType, d := editorValueTypeOkToTF(t.GetValueTypeOk())
		diags.Append(d...)

		attributeMap = map[string]attr.Value{
			"name":       framework.StringOkToTF(t.GetNameOk()),
			"type":       framework.EnumOkToTF(t.GetTypeOk()),
			"expression": framework.StringOkToTF(t.GetNameOk()),
			"value_type": valueType,
		}

	case authorize.AuthorizeEditorDataProcessorsXPathProcessorDTO:

		valueType, d := editorValueTypeOkToTF(t.GetValueTypeOk())
		diags.Append(d...)

		attributeMap = map[string]attr.Value{
			"name":       framework.StringOkToTF(t.GetNameOk()),
			"type":       framework.EnumOkToTF(t.GetTypeOk()),
			"expression": framework.StringOkToTF(t.GetNameOk()),
			"value_type": valueType,
		}

	default:
		tflog.Error(ctx, "Invalid processor type", map[string]interface{}{
			"processor type": t,
		})
		diags.AddError(
			"Invalid processor type",
			"The processor type is not supported.  Please raise an issue with the provider maintainers.",
		)
	}

	attributeMap = editorDataProcessorConvertEmptyValuesToTFNulls(attributeMap)

	objValue, d := types.ObjectValue(editorDataProcessorTFObjectTypes, attributeMap)
	diags.Append(d...)

	return objValue, diags
}

func editorDataProcessorConvertEmptyValuesToTFNulls(attributeMap map[string]attr.Value) map[string]attr.Value {
	nullMap := map[string]attr.Value{
		"name":          types.StringNull(),
		"type":          types.StringNull(),
		"processors":    types.ListNull(types.ObjectType{AttrTypes: editorDataProcessorTFObjectTypes}),
		"predicate":     types.ObjectNull(editorDataProcessorTFObjectTypes),
		"processor":     types.ObjectNull(editorDataProcessorTFObjectTypes),
		"expression":    types.StringNull(),
		"value_type":    types.ObjectNull(editorValueTypeTFObjectTypes),
		"processor_ref": types.ObjectNull(editorReferenceObjectTFObjectTypes),
	}

	for k := range nullMap {
		if attributeMap[k] == nil {
			attributeMap[k] = nullMap[k]
		}
	}

	return attributeMap
}
