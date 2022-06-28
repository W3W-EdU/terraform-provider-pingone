/*
PingOne Platform API - Management

A bare-bones collection for the PingOne API

API version: 1.0.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package pingone

import (
	"encoding/json"
)

// RiskEvaluationDetails struct for RiskEvaluationDetails
type RiskEvaluationDetails struct {
	IpAddressReputation *RiskEvaluationDetailsIpAddressReputation `json:"ipAddressReputation,omitempty"`
	IpVelocityByUser *RiskEvaluationDetailsIpVelocityByUser `json:"ipVelocityByUser,omitempty"`
	UserVelocityByIp *RiskEvaluationDetailsUserVelocityByIp `json:"userVelocityByIp,omitempty"`
	// A boolean that specifies whether the distance between the location of the user in their previous successful authentication and current authentication infers that the user had to travel at a speed greater than 1000 kilometers per hour. This condition is marked as fulfilled, only if: Location data is available for the current and previous IP address of the user. This is not the first transaction that the user has performed. The user’s previous successful transaction was performed less than 24 hours ago. The user moved a distance of at least 100 kilometers. Thus, even if the user moved very fast, but moved only a distance of 90 kilometers, the condition is not fulfilled. The user moved at a speed greater than 1000 kilometers per hour.
	ImpossibleTravel *bool `json:"impossibleTravel,omitempty"`
	// The calculated travel speed in units of kilometers per hour.
	EstimatedSpeed *float32 `json:"estimatedSpeed,omitempty"`
	// A boolean that specifies whether the current authentication originated from an anonymous network (for example, proxy or VPN).
	AnonymousNetworkDetected *bool `json:"anonymousNetworkDetected,omitempty"`
	// A string that specifies the country related to current transaction from the IP address.
	Country *string `json:"country,omitempty"`
	// A string that specifies the state related to current transaction from the IP address.
	State *string `json:"state,omitempty"`
	// A string that specifies the city related to current transaction from the IP address.
	City *string `json:"city,omitempty"`
	// A double-precision floating point that specifies the longitude related to current transaction from the IP address. Values range from -90 to 90.
	Longitude *float32 `json:"longitude,omitempty"`
	// A double-precision floating point that specifies the latitude related to current transaction from the IP address. Values range from -180 to 180.
	Latitude *float32 `json:"latitude,omitempty"`
	PreviousSuccessfulTransaction *RiskEvaluationDetailsPreviousSuccessfulTransaction `json:"previousSuccessfulTransaction,omitempty"`
	UserBasedRiskBehavior *RiskEvaluationDetailsUserBasedRiskBehavior `json:"userBasedRiskBehavior,omitempty"`
	UserRiskBehavior *RiskEvaluationDetailsUserRiskBehavior `json:"userRiskBehavior,omitempty"`
}

// NewRiskEvaluationDetails instantiates a new RiskEvaluationDetails object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewRiskEvaluationDetails() *RiskEvaluationDetails {
	this := RiskEvaluationDetails{}
	return &this
}

// NewRiskEvaluationDetailsWithDefaults instantiates a new RiskEvaluationDetails object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewRiskEvaluationDetailsWithDefaults() *RiskEvaluationDetails {
	this := RiskEvaluationDetails{}
	return &this
}

// GetIpAddressReputation returns the IpAddressReputation field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetIpAddressReputation() RiskEvaluationDetailsIpAddressReputation {
	if o == nil || o.IpAddressReputation == nil {
		var ret RiskEvaluationDetailsIpAddressReputation
		return ret
	}
	return *o.IpAddressReputation
}

// GetIpAddressReputationOk returns a tuple with the IpAddressReputation field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetIpAddressReputationOk() (*RiskEvaluationDetailsIpAddressReputation, bool) {
	if o == nil || o.IpAddressReputation == nil {
		return nil, false
	}
	return o.IpAddressReputation, true
}

// HasIpAddressReputation returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasIpAddressReputation() bool {
	if o != nil && o.IpAddressReputation != nil {
		return true
	}

	return false
}

// SetIpAddressReputation gets a reference to the given RiskEvaluationDetailsIpAddressReputation and assigns it to the IpAddressReputation field.
func (o *RiskEvaluationDetails) SetIpAddressReputation(v RiskEvaluationDetailsIpAddressReputation) {
	o.IpAddressReputation = &v
}

// GetIpVelocityByUser returns the IpVelocityByUser field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetIpVelocityByUser() RiskEvaluationDetailsIpVelocityByUser {
	if o == nil || o.IpVelocityByUser == nil {
		var ret RiskEvaluationDetailsIpVelocityByUser
		return ret
	}
	return *o.IpVelocityByUser
}

// GetIpVelocityByUserOk returns a tuple with the IpVelocityByUser field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetIpVelocityByUserOk() (*RiskEvaluationDetailsIpVelocityByUser, bool) {
	if o == nil || o.IpVelocityByUser == nil {
		return nil, false
	}
	return o.IpVelocityByUser, true
}

// HasIpVelocityByUser returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasIpVelocityByUser() bool {
	if o != nil && o.IpVelocityByUser != nil {
		return true
	}

	return false
}

// SetIpVelocityByUser gets a reference to the given RiskEvaluationDetailsIpVelocityByUser and assigns it to the IpVelocityByUser field.
func (o *RiskEvaluationDetails) SetIpVelocityByUser(v RiskEvaluationDetailsIpVelocityByUser) {
	o.IpVelocityByUser = &v
}

// GetUserVelocityByIp returns the UserVelocityByIp field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetUserVelocityByIp() RiskEvaluationDetailsUserVelocityByIp {
	if o == nil || o.UserVelocityByIp == nil {
		var ret RiskEvaluationDetailsUserVelocityByIp
		return ret
	}
	return *o.UserVelocityByIp
}

// GetUserVelocityByIpOk returns a tuple with the UserVelocityByIp field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetUserVelocityByIpOk() (*RiskEvaluationDetailsUserVelocityByIp, bool) {
	if o == nil || o.UserVelocityByIp == nil {
		return nil, false
	}
	return o.UserVelocityByIp, true
}

// HasUserVelocityByIp returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasUserVelocityByIp() bool {
	if o != nil && o.UserVelocityByIp != nil {
		return true
	}

	return false
}

// SetUserVelocityByIp gets a reference to the given RiskEvaluationDetailsUserVelocityByIp and assigns it to the UserVelocityByIp field.
func (o *RiskEvaluationDetails) SetUserVelocityByIp(v RiskEvaluationDetailsUserVelocityByIp) {
	o.UserVelocityByIp = &v
}

// GetImpossibleTravel returns the ImpossibleTravel field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetImpossibleTravel() bool {
	if o == nil || o.ImpossibleTravel == nil {
		var ret bool
		return ret
	}
	return *o.ImpossibleTravel
}

// GetImpossibleTravelOk returns a tuple with the ImpossibleTravel field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetImpossibleTravelOk() (*bool, bool) {
	if o == nil || o.ImpossibleTravel == nil {
		return nil, false
	}
	return o.ImpossibleTravel, true
}

// HasImpossibleTravel returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasImpossibleTravel() bool {
	if o != nil && o.ImpossibleTravel != nil {
		return true
	}

	return false
}

// SetImpossibleTravel gets a reference to the given bool and assigns it to the ImpossibleTravel field.
func (o *RiskEvaluationDetails) SetImpossibleTravel(v bool) {
	o.ImpossibleTravel = &v
}

// GetEstimatedSpeed returns the EstimatedSpeed field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetEstimatedSpeed() float32 {
	if o == nil || o.EstimatedSpeed == nil {
		var ret float32
		return ret
	}
	return *o.EstimatedSpeed
}

// GetEstimatedSpeedOk returns a tuple with the EstimatedSpeed field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetEstimatedSpeedOk() (*float32, bool) {
	if o == nil || o.EstimatedSpeed == nil {
		return nil, false
	}
	return o.EstimatedSpeed, true
}

// HasEstimatedSpeed returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasEstimatedSpeed() bool {
	if o != nil && o.EstimatedSpeed != nil {
		return true
	}

	return false
}

// SetEstimatedSpeed gets a reference to the given float32 and assigns it to the EstimatedSpeed field.
func (o *RiskEvaluationDetails) SetEstimatedSpeed(v float32) {
	o.EstimatedSpeed = &v
}

// GetAnonymousNetworkDetected returns the AnonymousNetworkDetected field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetAnonymousNetworkDetected() bool {
	if o == nil || o.AnonymousNetworkDetected == nil {
		var ret bool
		return ret
	}
	return *o.AnonymousNetworkDetected
}

// GetAnonymousNetworkDetectedOk returns a tuple with the AnonymousNetworkDetected field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetAnonymousNetworkDetectedOk() (*bool, bool) {
	if o == nil || o.AnonymousNetworkDetected == nil {
		return nil, false
	}
	return o.AnonymousNetworkDetected, true
}

// HasAnonymousNetworkDetected returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasAnonymousNetworkDetected() bool {
	if o != nil && o.AnonymousNetworkDetected != nil {
		return true
	}

	return false
}

// SetAnonymousNetworkDetected gets a reference to the given bool and assigns it to the AnonymousNetworkDetected field.
func (o *RiskEvaluationDetails) SetAnonymousNetworkDetected(v bool) {
	o.AnonymousNetworkDetected = &v
}

// GetCountry returns the Country field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetCountry() string {
	if o == nil || o.Country == nil {
		var ret string
		return ret
	}
	return *o.Country
}

// GetCountryOk returns a tuple with the Country field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetCountryOk() (*string, bool) {
	if o == nil || o.Country == nil {
		return nil, false
	}
	return o.Country, true
}

// HasCountry returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasCountry() bool {
	if o != nil && o.Country != nil {
		return true
	}

	return false
}

// SetCountry gets a reference to the given string and assigns it to the Country field.
func (o *RiskEvaluationDetails) SetCountry(v string) {
	o.Country = &v
}

// GetState returns the State field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetState() string {
	if o == nil || o.State == nil {
		var ret string
		return ret
	}
	return *o.State
}

// GetStateOk returns a tuple with the State field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetStateOk() (*string, bool) {
	if o == nil || o.State == nil {
		return nil, false
	}
	return o.State, true
}

// HasState returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasState() bool {
	if o != nil && o.State != nil {
		return true
	}

	return false
}

// SetState gets a reference to the given string and assigns it to the State field.
func (o *RiskEvaluationDetails) SetState(v string) {
	o.State = &v
}

// GetCity returns the City field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetCity() string {
	if o == nil || o.City == nil {
		var ret string
		return ret
	}
	return *o.City
}

// GetCityOk returns a tuple with the City field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetCityOk() (*string, bool) {
	if o == nil || o.City == nil {
		return nil, false
	}
	return o.City, true
}

// HasCity returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasCity() bool {
	if o != nil && o.City != nil {
		return true
	}

	return false
}

// SetCity gets a reference to the given string and assigns it to the City field.
func (o *RiskEvaluationDetails) SetCity(v string) {
	o.City = &v
}

// GetLongitude returns the Longitude field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetLongitude() float32 {
	if o == nil || o.Longitude == nil {
		var ret float32
		return ret
	}
	return *o.Longitude
}

// GetLongitudeOk returns a tuple with the Longitude field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetLongitudeOk() (*float32, bool) {
	if o == nil || o.Longitude == nil {
		return nil, false
	}
	return o.Longitude, true
}

// HasLongitude returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasLongitude() bool {
	if o != nil && o.Longitude != nil {
		return true
	}

	return false
}

// SetLongitude gets a reference to the given float32 and assigns it to the Longitude field.
func (o *RiskEvaluationDetails) SetLongitude(v float32) {
	o.Longitude = &v
}

// GetLatitude returns the Latitude field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetLatitude() float32 {
	if o == nil || o.Latitude == nil {
		var ret float32
		return ret
	}
	return *o.Latitude
}

// GetLatitudeOk returns a tuple with the Latitude field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetLatitudeOk() (*float32, bool) {
	if o == nil || o.Latitude == nil {
		return nil, false
	}
	return o.Latitude, true
}

// HasLatitude returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasLatitude() bool {
	if o != nil && o.Latitude != nil {
		return true
	}

	return false
}

// SetLatitude gets a reference to the given float32 and assigns it to the Latitude field.
func (o *RiskEvaluationDetails) SetLatitude(v float32) {
	o.Latitude = &v
}

// GetPreviousSuccessfulTransaction returns the PreviousSuccessfulTransaction field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetPreviousSuccessfulTransaction() RiskEvaluationDetailsPreviousSuccessfulTransaction {
	if o == nil || o.PreviousSuccessfulTransaction == nil {
		var ret RiskEvaluationDetailsPreviousSuccessfulTransaction
		return ret
	}
	return *o.PreviousSuccessfulTransaction
}

// GetPreviousSuccessfulTransactionOk returns a tuple with the PreviousSuccessfulTransaction field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetPreviousSuccessfulTransactionOk() (*RiskEvaluationDetailsPreviousSuccessfulTransaction, bool) {
	if o == nil || o.PreviousSuccessfulTransaction == nil {
		return nil, false
	}
	return o.PreviousSuccessfulTransaction, true
}

// HasPreviousSuccessfulTransaction returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasPreviousSuccessfulTransaction() bool {
	if o != nil && o.PreviousSuccessfulTransaction != nil {
		return true
	}

	return false
}

// SetPreviousSuccessfulTransaction gets a reference to the given RiskEvaluationDetailsPreviousSuccessfulTransaction and assigns it to the PreviousSuccessfulTransaction field.
func (o *RiskEvaluationDetails) SetPreviousSuccessfulTransaction(v RiskEvaluationDetailsPreviousSuccessfulTransaction) {
	o.PreviousSuccessfulTransaction = &v
}

// GetUserBasedRiskBehavior returns the UserBasedRiskBehavior field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetUserBasedRiskBehavior() RiskEvaluationDetailsUserBasedRiskBehavior {
	if o == nil || o.UserBasedRiskBehavior == nil {
		var ret RiskEvaluationDetailsUserBasedRiskBehavior
		return ret
	}
	return *o.UserBasedRiskBehavior
}

// GetUserBasedRiskBehaviorOk returns a tuple with the UserBasedRiskBehavior field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetUserBasedRiskBehaviorOk() (*RiskEvaluationDetailsUserBasedRiskBehavior, bool) {
	if o == nil || o.UserBasedRiskBehavior == nil {
		return nil, false
	}
	return o.UserBasedRiskBehavior, true
}

// HasUserBasedRiskBehavior returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasUserBasedRiskBehavior() bool {
	if o != nil && o.UserBasedRiskBehavior != nil {
		return true
	}

	return false
}

// SetUserBasedRiskBehavior gets a reference to the given RiskEvaluationDetailsUserBasedRiskBehavior and assigns it to the UserBasedRiskBehavior field.
func (o *RiskEvaluationDetails) SetUserBasedRiskBehavior(v RiskEvaluationDetailsUserBasedRiskBehavior) {
	o.UserBasedRiskBehavior = &v
}

// GetUserRiskBehavior returns the UserRiskBehavior field value if set, zero value otherwise.
func (o *RiskEvaluationDetails) GetUserRiskBehavior() RiskEvaluationDetailsUserRiskBehavior {
	if o == nil || o.UserRiskBehavior == nil {
		var ret RiskEvaluationDetailsUserRiskBehavior
		return ret
	}
	return *o.UserRiskBehavior
}

// GetUserRiskBehaviorOk returns a tuple with the UserRiskBehavior field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RiskEvaluationDetails) GetUserRiskBehaviorOk() (*RiskEvaluationDetailsUserRiskBehavior, bool) {
	if o == nil || o.UserRiskBehavior == nil {
		return nil, false
	}
	return o.UserRiskBehavior, true
}

// HasUserRiskBehavior returns a boolean if a field has been set.
func (o *RiskEvaluationDetails) HasUserRiskBehavior() bool {
	if o != nil && o.UserRiskBehavior != nil {
		return true
	}

	return false
}

// SetUserRiskBehavior gets a reference to the given RiskEvaluationDetailsUserRiskBehavior and assigns it to the UserRiskBehavior field.
func (o *RiskEvaluationDetails) SetUserRiskBehavior(v RiskEvaluationDetailsUserRiskBehavior) {
	o.UserRiskBehavior = &v
}

func (o RiskEvaluationDetails) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.IpAddressReputation != nil {
		toSerialize["ipAddressReputation"] = o.IpAddressReputation
	}
	if o.IpVelocityByUser != nil {
		toSerialize["ipVelocityByUser"] = o.IpVelocityByUser
	}
	if o.UserVelocityByIp != nil {
		toSerialize["userVelocityByIp"] = o.UserVelocityByIp
	}
	if o.ImpossibleTravel != nil {
		toSerialize["impossibleTravel"] = o.ImpossibleTravel
	}
	if o.EstimatedSpeed != nil {
		toSerialize["estimatedSpeed"] = o.EstimatedSpeed
	}
	if o.AnonymousNetworkDetected != nil {
		toSerialize["anonymousNetworkDetected"] = o.AnonymousNetworkDetected
	}
	if o.Country != nil {
		toSerialize["country"] = o.Country
	}
	if o.State != nil {
		toSerialize["state"] = o.State
	}
	if o.City != nil {
		toSerialize["city"] = o.City
	}
	if o.Longitude != nil {
		toSerialize["longitude"] = o.Longitude
	}
	if o.Latitude != nil {
		toSerialize["latitude"] = o.Latitude
	}
	if o.PreviousSuccessfulTransaction != nil {
		toSerialize["previousSuccessfulTransaction"] = o.PreviousSuccessfulTransaction
	}
	if o.UserBasedRiskBehavior != nil {
		toSerialize["userBasedRiskBehavior"] = o.UserBasedRiskBehavior
	}
	if o.UserRiskBehavior != nil {
		toSerialize["userRiskBehavior"] = o.UserRiskBehavior
	}
	return json.Marshal(toSerialize)
}

type NullableRiskEvaluationDetails struct {
	value *RiskEvaluationDetails
	isSet bool
}

func (v NullableRiskEvaluationDetails) Get() *RiskEvaluationDetails {
	return v.value
}

func (v *NullableRiskEvaluationDetails) Set(val *RiskEvaluationDetails) {
	v.value = val
	v.isSet = true
}

func (v NullableRiskEvaluationDetails) IsSet() bool {
	return v.isSet
}

func (v *NullableRiskEvaluationDetails) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableRiskEvaluationDetails(val *RiskEvaluationDetails) *NullableRiskEvaluationDetails {
	return &NullableRiskEvaluationDetails{value: val, isSet: true}
}

func (v NullableRiskEvaluationDetails) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableRiskEvaluationDetails) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


