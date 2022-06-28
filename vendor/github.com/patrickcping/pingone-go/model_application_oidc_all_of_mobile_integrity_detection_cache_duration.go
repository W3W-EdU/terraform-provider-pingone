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

// ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration struct for ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration
type ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration struct {
	// An integer that specifies the number of minutes or hours that specify the duration between successful integrity detection calls. Every attestation request entails a certain time tradeoff. You can choose to cache successful integrity detection calls for a predefined duration, between a minimum of 1 minute and a maximum of 48 hours. If mobile.integrityDetection.mode is ENABLED, the cache duration must be set.
	Amount *int32 `json:"amount,omitempty"`
	// A string that specifies the time units of the mobile.integrityDetection.cacheDuration.amount :MINUTES, HOURS
	Units *string `json:"units,omitempty"`
}

// NewApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration instantiates a new ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration() *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration {
	this := ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration{}
	return &this
}

// NewApplicationOIDCAllOfMobileIntegrityDetectionCacheDurationWithDefaults instantiates a new ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewApplicationOIDCAllOfMobileIntegrityDetectionCacheDurationWithDefaults() *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration {
	this := ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration{}
	return &this
}

// GetAmount returns the Amount field value if set, zero value otherwise.
func (o *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) GetAmount() int32 {
	if o == nil || o.Amount == nil {
		var ret int32
		return ret
	}
	return *o.Amount
}

// GetAmountOk returns a tuple with the Amount field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) GetAmountOk() (*int32, bool) {
	if o == nil || o.Amount == nil {
		return nil, false
	}
	return o.Amount, true
}

// HasAmount returns a boolean if a field has been set.
func (o *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) HasAmount() bool {
	if o != nil && o.Amount != nil {
		return true
	}

	return false
}

// SetAmount gets a reference to the given int32 and assigns it to the Amount field.
func (o *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) SetAmount(v int32) {
	o.Amount = &v
}

// GetUnits returns the Units field value if set, zero value otherwise.
func (o *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) GetUnits() string {
	if o == nil || o.Units == nil {
		var ret string
		return ret
	}
	return *o.Units
}

// GetUnitsOk returns a tuple with the Units field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) GetUnitsOk() (*string, bool) {
	if o == nil || o.Units == nil {
		return nil, false
	}
	return o.Units, true
}

// HasUnits returns a boolean if a field has been set.
func (o *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) HasUnits() bool {
	if o != nil && o.Units != nil {
		return true
	}

	return false
}

// SetUnits gets a reference to the given string and assigns it to the Units field.
func (o *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) SetUnits(v string) {
	o.Units = &v
}

func (o ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Amount != nil {
		toSerialize["amount"] = o.Amount
	}
	if o.Units != nil {
		toSerialize["units"] = o.Units
	}
	return json.Marshal(toSerialize)
}

type NullableApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration struct {
	value *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration
	isSet bool
}

func (v NullableApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) Get() *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration {
	return v.value
}

func (v *NullableApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) Set(val *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) {
	v.value = val
	v.isSet = true
}

func (v NullableApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) IsSet() bool {
	return v.isSet
}

func (v *NullableApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration(val *ApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) *NullableApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration {
	return &NullableApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration{value: val, isSet: true}
}

func (v NullableApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableApplicationOIDCAllOfMobileIntegrityDetectionCacheDuration) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


