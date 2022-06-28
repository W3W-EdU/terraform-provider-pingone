/*
PingOne Platform API - Management

A bare-bones collection for the PingOne API

API version: 1.0.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package pingone

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)


// ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApi service
type ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService service

type ApiV1EnvironmentsEnvIDPropagationStoreMetadataAqueraPostRequest struct {
	ctx context.Context
	ApiService *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService
	envID string
	body *map[string]interface{}
}

func (r ApiV1EnvironmentsEnvIDPropagationStoreMetadataAqueraPostRequest) Body(body map[string]interface{}) ApiV1EnvironmentsEnvIDPropagationStoreMetadataAqueraPostRequest {
	r.body = &body
	return r
}

func (r ApiV1EnvironmentsEnvIDPropagationStoreMetadataAqueraPostRequest) Execute() (*http.Response, error) {
	return r.ApiService.V1EnvironmentsEnvIDPropagationStoreMetadataAqueraPostExecute(r)
}

/*
V1EnvironmentsEnvIDPropagationStoreMetadataAqueraPost Identity Propagation Store Metadata (Aquera)

By design, PingOne requests solely comprise this collection. For complete documentation, direct a browser to <a href='https://apidocs.pingidentity.com/pingone/platform/v1/api/'>apidocs.pingidentity.com</a>.

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param envID
 @return ApiV1EnvironmentsEnvIDPropagationStoreMetadataAqueraPostRequest
*/
func (a *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService) V1EnvironmentsEnvIDPropagationStoreMetadataAqueraPost(ctx context.Context, envID string) ApiV1EnvironmentsEnvIDPropagationStoreMetadataAqueraPostRequest {
	return ApiV1EnvironmentsEnvIDPropagationStoreMetadataAqueraPostRequest{
		ApiService: a,
		ctx: ctx,
		envID: envID,
	}
}

// Execute executes the request
func (a *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService) V1EnvironmentsEnvIDPropagationStoreMetadataAqueraPostExecute(r ApiV1EnvironmentsEnvIDPropagationStoreMetadataAqueraPostRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPost
		localVarPostBody     interface{}
		formFiles            []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService.V1EnvironmentsEnvIDPropagationStoreMetadataAqueraPost")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/environments/{envID}/propagation/storeMetadata/Aquera"
	localVarPath = strings.Replace(localVarPath, "{"+"envID"+"}", url.PathEscape(parameterToString(r.envID, "")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	// body params
	localVarPostBody = r.body
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarHTTPResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 401 {
			var v P1Error
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		return localVarHTTPResponse, newErr
	}

	return localVarHTTPResponse, nil
}

type ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPostRequest struct {
	ctx context.Context
	ApiService *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService
	envID string
	body *map[string]interface{}
}

func (r ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPostRequest) Body(body map[string]interface{}) ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPostRequest {
	r.body = &body
	return r
}

func (r ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPostRequest) Execute() (*http.Response, error) {
	return r.ApiService.V1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPostExecute(r)
}

/*
V1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPost Identity Propagation Store Metadata (SalesforceContacts)

By design, PingOne requests solely comprise this collection. For complete documentation, direct a browser to <a href='https://apidocs.pingidentity.com/pingone/platform/v1/api/'>apidocs.pingidentity.com</a>.

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param envID
 @return ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPostRequest
*/
func (a *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService) V1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPost(ctx context.Context, envID string) ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPostRequest {
	return ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPostRequest{
		ApiService: a,
		ctx: ctx,
		envID: envID,
	}
}

// Execute executes the request
func (a *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService) V1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPostExecute(r ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPostRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPost
		localVarPostBody     interface{}
		formFiles            []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService.V1EnvironmentsEnvIDPropagationStoreMetadataSalesforceContactsPost")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/environments/{envID}/propagation/storeMetadata/SalesforceContacts"
	localVarPath = strings.Replace(localVarPath, "{"+"envID"+"}", url.PathEscape(parameterToString(r.envID, "")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	// body params
	localVarPostBody = r.body
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarHTTPResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 401 {
			var v P1Error
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		return localVarHTTPResponse, newErr
	}

	return localVarHTTPResponse, nil
}

type ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePostRequest struct {
	ctx context.Context
	ApiService *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService
	envID string
	body *map[string]interface{}
}

func (r ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePostRequest) Body(body map[string]interface{}) ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePostRequest {
	r.body = &body
	return r
}

func (r ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePostRequest) Execute() (*http.Response, error) {
	return r.ApiService.V1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePostExecute(r)
}

/*
V1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePost Identity Propagation Store Metadata (Salesforce)

By design, PingOne requests solely comprise this collection. For complete documentation, direct a browser to <a href='https://apidocs.pingidentity.com/pingone/platform/v1/api/'>apidocs.pingidentity.com</a>.

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param envID
 @return ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePostRequest
*/
func (a *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService) V1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePost(ctx context.Context, envID string) ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePostRequest {
	return ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePostRequest{
		ApiService: a,
		ctx: ctx,
		envID: envID,
	}
}

// Execute executes the request
func (a *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService) V1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePostExecute(r ApiV1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePostRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPost
		localVarPostBody     interface{}
		formFiles            []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService.V1EnvironmentsEnvIDPropagationStoreMetadataSalesforcePost")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/environments/{envID}/propagation/storeMetadata/Salesforce"
	localVarPath = strings.Replace(localVarPath, "{"+"envID"+"}", url.PathEscape(parameterToString(r.envID, "")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	// body params
	localVarPostBody = r.body
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarHTTPResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 401 {
			var v P1Error
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		return localVarHTTPResponse, newErr
	}

	return localVarHTTPResponse, nil
}

type ApiV1EnvironmentsEnvIDPropagationStoreMetadataScimPostRequest struct {
	ctx context.Context
	ApiService *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService
	envID string
	body *map[string]interface{}
}

func (r ApiV1EnvironmentsEnvIDPropagationStoreMetadataScimPostRequest) Body(body map[string]interface{}) ApiV1EnvironmentsEnvIDPropagationStoreMetadataScimPostRequest {
	r.body = &body
	return r
}

func (r ApiV1EnvironmentsEnvIDPropagationStoreMetadataScimPostRequest) Execute() (*http.Response, error) {
	return r.ApiService.V1EnvironmentsEnvIDPropagationStoreMetadataScimPostExecute(r)
}

/*
V1EnvironmentsEnvIDPropagationStoreMetadataScimPost Identity Propagation Store Metadata (SCIM)

By design, PingOne requests solely comprise this collection. For complete documentation, direct a browser to <a href='https://apidocs.pingidentity.com/pingone/platform/v1/api/'>apidocs.pingidentity.com</a>.

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param envID
 @return ApiV1EnvironmentsEnvIDPropagationStoreMetadataScimPostRequest
*/
func (a *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService) V1EnvironmentsEnvIDPropagationStoreMetadataScimPost(ctx context.Context, envID string) ApiV1EnvironmentsEnvIDPropagationStoreMetadataScimPostRequest {
	return ApiV1EnvironmentsEnvIDPropagationStoreMetadataScimPostRequest{
		ApiService: a,
		ctx: ctx,
		envID: envID,
	}
}

// Execute executes the request
func (a *ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService) V1EnvironmentsEnvIDPropagationStoreMetadataScimPostExecute(r ApiV1EnvironmentsEnvIDPropagationStoreMetadataScimPostRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPost
		localVarPostBody     interface{}
		formFiles            []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ManagementAPIsIdentityPropagationProvisioningPropagationStoreMetadataApiService.V1EnvironmentsEnvIDPropagationStoreMetadataScimPost")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/environments/{envID}/propagation/storeMetadata/scim"
	localVarPath = strings.Replace(localVarPath, "{"+"envID"+"}", url.PathEscape(parameterToString(r.envID, "")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	// body params
	localVarPostBody = r.body
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarHTTPResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 401 {
			var v P1Error
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		return localVarHTTPResponse, newErr
	}

	return localVarHTTPResponse, nil
}
