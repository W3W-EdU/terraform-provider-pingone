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


// ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService ManagementAPIsApplicationsApplicationMFAPushCredentialsApi service
type ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService service

type ApiCreateMFAPushCredentialRequest struct {
	ctx context.Context
	ApiService *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService
	envID string
	appID string
	createMFAPushCredentialRequest *CreateMFAPushCredentialRequest
}

func (r ApiCreateMFAPushCredentialRequest) CreateMFAPushCredentialRequest(createMFAPushCredentialRequest CreateMFAPushCredentialRequest) ApiCreateMFAPushCredentialRequest {
	r.createMFAPushCredentialRequest = &createMFAPushCredentialRequest
	return r
}

func (r ApiCreateMFAPushCredentialRequest) Execute() (*CreateMFAPushCredential201Response, *http.Response, error) {
	return r.ApiService.CreateMFAPushCredentialExecute(r)
}

/*
CreateMFAPushCredential CREATE MFA Push Credential

By design, PingOne requests solely comprise this collection. For complete documentation, direct a browser to <a href='https://apidocs.pingidentity.com/pingone/platform/v1/api/'>apidocs.pingidentity.com</a>.

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param envID
 @param appID
 @return ApiCreateMFAPushCredentialRequest
*/
func (a *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService) CreateMFAPushCredential(ctx context.Context, envID string, appID string) ApiCreateMFAPushCredentialRequest {
	return ApiCreateMFAPushCredentialRequest{
		ApiService: a,
		ctx: ctx,
		envID: envID,
		appID: appID,
	}
}

// Execute executes the request
//  @return CreateMFAPushCredential201Response
func (a *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService) CreateMFAPushCredentialExecute(r ApiCreateMFAPushCredentialRequest) (*CreateMFAPushCredential201Response, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPost
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *CreateMFAPushCredential201Response
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService.CreateMFAPushCredential")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/environments/{envID}/applications/{appID}/pushCredentials"
	localVarPath = strings.Replace(localVarPath, "{"+"envID"+"}", url.PathEscape(parameterToString(r.envID, "")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"appID"+"}", url.PathEscape(parameterToString(r.appID, "")), -1)

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
	localVarPostBody = r.createMFAPushCredentialRequest
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
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
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiDeleteMFAPushCredentialRequest struct {
	ctx context.Context
	ApiService *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService
	envID string
	appID string
	pushCredID string
	authorization *string
}

func (r ApiDeleteMFAPushCredentialRequest) Authorization(authorization string) ApiDeleteMFAPushCredentialRequest {
	r.authorization = &authorization
	return r
}

func (r ApiDeleteMFAPushCredentialRequest) Execute() (*http.Response, error) {
	return r.ApiService.DeleteMFAPushCredentialExecute(r)
}

/*
DeleteMFAPushCredential DELETE MFA Push Credential

By design, PingOne requests solely comprise this collection. For complete documentation, direct a browser to <a href='https://apidocs.pingidentity.com/pingone/platform/v1/api/'>apidocs.pingidentity.com</a>.

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param envID
 @param appID
 @param pushCredID
 @return ApiDeleteMFAPushCredentialRequest
*/
func (a *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService) DeleteMFAPushCredential(ctx context.Context, envID string, appID string, pushCredID string) ApiDeleteMFAPushCredentialRequest {
	return ApiDeleteMFAPushCredentialRequest{
		ApiService: a,
		ctx: ctx,
		envID: envID,
		appID: appID,
		pushCredID: pushCredID,
	}
}

// Execute executes the request
func (a *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService) DeleteMFAPushCredentialExecute(r ApiDeleteMFAPushCredentialRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodDelete
		localVarPostBody     interface{}
		formFiles            []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService.DeleteMFAPushCredential")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/environments/{envID}/applications/{appID}/pushCredentials/{pushCredID}"
	localVarPath = strings.Replace(localVarPath, "{"+"envID"+"}", url.PathEscape(parameterToString(r.envID, "")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"appID"+"}", url.PathEscape(parameterToString(r.appID, "")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"pushCredID"+"}", url.PathEscape(parameterToString(r.pushCredID, "")), -1)

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
	if r.authorization != nil {
		localVarHeaderParams["Authorization"] = parameterToString(*r.authorization, "")
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

type ApiReadAllMFAPushCredentialsRequest struct {
	ctx context.Context
	ApiService *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService
	envID string
	appID string
}

func (r ApiReadAllMFAPushCredentialsRequest) Execute() (*EntityArray, *http.Response, error) {
	return r.ApiService.ReadAllMFAPushCredentialsExecute(r)
}

/*
ReadAllMFAPushCredentials READ All MFA Push Credentials

By design, PingOne requests solely comprise this collection. For complete documentation, direct a browser to <a href='https://apidocs.pingidentity.com/pingone/platform/v1/api/'>apidocs.pingidentity.com</a>.

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param envID
 @param appID
 @return ApiReadAllMFAPushCredentialsRequest
*/
func (a *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService) ReadAllMFAPushCredentials(ctx context.Context, envID string, appID string) ApiReadAllMFAPushCredentialsRequest {
	return ApiReadAllMFAPushCredentialsRequest{
		ApiService: a,
		ctx: ctx,
		envID: envID,
		appID: appID,
	}
}

// Execute executes the request
//  @return EntityArray
func (a *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService) ReadAllMFAPushCredentialsExecute(r ApiReadAllMFAPushCredentialsRequest) (*EntityArray, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *EntityArray
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService.ReadAllMFAPushCredentials")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/environments/{envID}/applications/{appID}/pushCredentials"
	localVarPath = strings.Replace(localVarPath, "{"+"envID"+"}", url.PathEscape(parameterToString(r.envID, "")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"appID"+"}", url.PathEscape(parameterToString(r.appID, "")), -1)

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
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
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
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiReadOneMFAPushCredentialRequest struct {
	ctx context.Context
	ApiService *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService
	envID string
	appID string
	pushCredID string
}

func (r ApiReadOneMFAPushCredentialRequest) Execute() (*CreateMFAPushCredential201Response, *http.Response, error) {
	return r.ApiService.ReadOneMFAPushCredentialExecute(r)
}

/*
ReadOneMFAPushCredential READ One MFA Push Credential

By design, PingOne requests solely comprise this collection. For complete documentation, direct a browser to <a href='https://apidocs.pingidentity.com/pingone/platform/v1/api/'>apidocs.pingidentity.com</a>.

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param envID
 @param appID
 @param pushCredID
 @return ApiReadOneMFAPushCredentialRequest
*/
func (a *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService) ReadOneMFAPushCredential(ctx context.Context, envID string, appID string, pushCredID string) ApiReadOneMFAPushCredentialRequest {
	return ApiReadOneMFAPushCredentialRequest{
		ApiService: a,
		ctx: ctx,
		envID: envID,
		appID: appID,
		pushCredID: pushCredID,
	}
}

// Execute executes the request
//  @return CreateMFAPushCredential201Response
func (a *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService) ReadOneMFAPushCredentialExecute(r ApiReadOneMFAPushCredentialRequest) (*CreateMFAPushCredential201Response, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *CreateMFAPushCredential201Response
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService.ReadOneMFAPushCredential")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/environments/{envID}/applications/{appID}/pushCredentials/{pushCredID}"
	localVarPath = strings.Replace(localVarPath, "{"+"envID"+"}", url.PathEscape(parameterToString(r.envID, "")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"appID"+"}", url.PathEscape(parameterToString(r.appID, "")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"pushCredID"+"}", url.PathEscape(parameterToString(r.pushCredID, "")), -1)

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
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
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
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiUpdateMFAPushCredentialRequest struct {
	ctx context.Context
	ApiService *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService
	envID string
	appID string
	pushCredID string
	updateMFAPushCredentialRequest *UpdateMFAPushCredentialRequest
}

func (r ApiUpdateMFAPushCredentialRequest) UpdateMFAPushCredentialRequest(updateMFAPushCredentialRequest UpdateMFAPushCredentialRequest) ApiUpdateMFAPushCredentialRequest {
	r.updateMFAPushCredentialRequest = &updateMFAPushCredentialRequest
	return r
}

func (r ApiUpdateMFAPushCredentialRequest) Execute() (*CreateMFAPushCredential201Response, *http.Response, error) {
	return r.ApiService.UpdateMFAPushCredentialExecute(r)
}

/*
UpdateMFAPushCredential UPDATE MFA Push Credential

By design, PingOne requests solely comprise this collection. For complete documentation, direct a browser to <a href='https://apidocs.pingidentity.com/pingone/platform/v1/api/'>apidocs.pingidentity.com</a>.

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param envID
 @param appID
 @param pushCredID
 @return ApiUpdateMFAPushCredentialRequest
*/
func (a *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService) UpdateMFAPushCredential(ctx context.Context, envID string, appID string, pushCredID string) ApiUpdateMFAPushCredentialRequest {
	return ApiUpdateMFAPushCredentialRequest{
		ApiService: a,
		ctx: ctx,
		envID: envID,
		appID: appID,
		pushCredID: pushCredID,
	}
}

// Execute executes the request
//  @return CreateMFAPushCredential201Response
func (a *ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService) UpdateMFAPushCredentialExecute(r ApiUpdateMFAPushCredentialRequest) (*CreateMFAPushCredential201Response, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPut
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *CreateMFAPushCredential201Response
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ManagementAPIsApplicationsApplicationMFAPushCredentialsApiService.UpdateMFAPushCredential")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/environments/{envID}/applications/{appID}/pushCredentials/{pushCredID}"
	localVarPath = strings.Replace(localVarPath, "{"+"envID"+"}", url.PathEscape(parameterToString(r.envID, "")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"appID"+"}", url.PathEscape(parameterToString(r.appID, "")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"pushCredID"+"}", url.PathEscape(parameterToString(r.pushCredID, "")), -1)

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
	localVarPostBody = r.updateMFAPushCredentialRequest
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
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
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}
