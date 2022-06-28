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


// ManagementAPIsDeviceAuthenticationPolicyApiService ManagementAPIsDeviceAuthenticationPolicyApi service
type ManagementAPIsDeviceAuthenticationPolicyApiService service

type ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPutRequest struct {
	ctx context.Context
	ApiService *ManagementAPIsDeviceAuthenticationPolicyApiService
	envID string
	deviceAuthPolicyID string
	body *map[string]interface{}
}

func (r ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPutRequest) Body(body map[string]interface{}) ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPutRequest {
	r.body = &body
	return r
}

func (r ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPutRequest) Execute() (*http.Response, error) {
	return r.ApiService.V1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPutExecute(r)
}

/*
V1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPut UPDATE Device Authentication Policy

By design, PingOne requests solely comprise this collection. For complete documentation, direct a browser to <a href='https://apidocs.pingidentity.com/pingone/platform/v1/api/'>apidocs.pingidentity.com</a>.

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param envID
 @param deviceAuthPolicyID
 @return ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPutRequest
*/
func (a *ManagementAPIsDeviceAuthenticationPolicyApiService) V1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPut(ctx context.Context, envID string, deviceAuthPolicyID string) ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPutRequest {
	return ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPutRequest{
		ApiService: a,
		ctx: ctx,
		envID: envID,
		deviceAuthPolicyID: deviceAuthPolicyID,
	}
}

// Execute executes the request
func (a *ManagementAPIsDeviceAuthenticationPolicyApiService) V1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPutExecute(r ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPutRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPut
		localVarPostBody     interface{}
		formFiles            []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ManagementAPIsDeviceAuthenticationPolicyApiService.V1EnvironmentsEnvIDDeviceAuthenticationPolicyDeviceAuthPolicyIDPut")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/environments/{envID}/deviceAuthenticationPolicy/{deviceAuthPolicyID}"
	localVarPath = strings.Replace(localVarPath, "{"+"envID"+"}", url.PathEscape(parameterToString(r.envID, "")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"deviceAuthPolicyID"+"}", url.PathEscape(parameterToString(r.deviceAuthPolicyID, "")), -1)

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

type ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyGetRequest struct {
	ctx context.Context
	ApiService *ManagementAPIsDeviceAuthenticationPolicyApiService
	envID string
}

func (r ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyGetRequest) Execute() (*http.Response, error) {
	return r.ApiService.V1EnvironmentsEnvIDDeviceAuthenticationPolicyGetExecute(r)
}

/*
V1EnvironmentsEnvIDDeviceAuthenticationPolicyGet READ Device Authentication Policy

By design, PingOne requests solely comprise this collection. For complete documentation, direct a browser to <a href='https://apidocs.pingidentity.com/pingone/platform/v1/api/'>apidocs.pingidentity.com</a>.

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param envID
 @return ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyGetRequest
*/
func (a *ManagementAPIsDeviceAuthenticationPolicyApiService) V1EnvironmentsEnvIDDeviceAuthenticationPolicyGet(ctx context.Context, envID string) ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyGetRequest {
	return ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyGetRequest{
		ApiService: a,
		ctx: ctx,
		envID: envID,
	}
}

// Execute executes the request
func (a *ManagementAPIsDeviceAuthenticationPolicyApiService) V1EnvironmentsEnvIDDeviceAuthenticationPolicyGetExecute(r ApiV1EnvironmentsEnvIDDeviceAuthenticationPolicyGetRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ManagementAPIsDeviceAuthenticationPolicyApiService.V1EnvironmentsEnvIDDeviceAuthenticationPolicyGet")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/environments/{envID}/deviceAuthenticationPolicy"
	localVarPath = strings.Replace(localVarPath, "{"+"envID"+"}", url.PathEscape(parameterToString(r.envID, "")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

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
