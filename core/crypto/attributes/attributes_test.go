/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package attributes

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	pb "github.com/hyperledger/fabric/core/crypto/attributes/proto"
	"github.com/hyperledger/fabric/core/crypto/primitives"
)

func TestMain(m *testing.M) {
	if err := primitives.InitSecurityLevel("SHA3", 256); err != nil {
		fmt.Printf("Failed setting security level: %v", err)
	}

	ret := m.Run()
	os.Exit(ret)
}

func TestEncryptDecryptAttributeValuePK0(t *testing.T) {
	expected := "ACompany"

	preK0 := []byte{
		91, 206, 163, 104, 247, 74, 149, 209, 91, 137, 215, 236,
		84, 135, 9, 70, 160, 138, 89, 163, 240, 223, 83, 164, 58,
		208, 199, 23, 221, 123, 53, 220, 15, 41, 28, 111, 166,
		28, 29, 187, 97, 229, 117, 117, 49, 192, 134, 31, 151}

	encryptedAttribute, err := EncryptAttributeValuePK0(preK0, "company", []byte(expected))
	if err != nil {
		t.Error(err)
	}

	attributeKey := GetAttributeKey(preK0, "company")

	attribute, err := DecryptAttributeValue(attributeKey, encryptedAttribute)
	if err != nil {
		t.Error(err)
	}

	if string(attribute) != expected {
		t.Errorf("Failed decrypting attribute. Expected: %v, Actual: %v", expected, attribute)
	}
}

func TestGetKAndValueForAttribute(t *testing.T) {
	expected := "Software Engineer"

	tcert, prek0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	_, attribute, err := getKAndValueForAttribute("position", prek0, tcert)
	if err != nil {
		t.Error(err)
	}

	if string(attribute) != expected {
		t.Errorf("Failed retrieving attribute value from TCert. Expected: %v, Actual: %v", expected, string(attribute))
	}
}

func TestGetKAndValueForAttribute_MissingAttribute(t *testing.T) {
	tcert, prek0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	_, _, err = getKAndValueForAttribute("business_unit", prek0, tcert)
	if err == nil {
		t.Errorf("Trying to read an attribute that is not part of the TCert should produce an error")
	}
}

func TestGetValueForAttribute(t *testing.T) {
	expected := "Software Engineer"

	tcert, prek0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	value, err := GetValueForAttribute("position", prek0, tcert)
	if err != nil {
		t.Error(err)
	}

	if string(value) != expected {
		t.Errorf("Failed retrieving attribute value from TCert. Expected: %v, Actual: %v", expected, string(value))
	}
}

func TestGetValueForAttribute_MissingAttribute(t *testing.T) {
	tcert, prek0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	_, err = GetValueForAttribute("business_unit", prek0, tcert)
	if err == nil {
		t.Errorf("Trying to read an attribute that is not part of the TCert should produce an error")
	}
}

func TestGetKForAttribute(t *testing.T) {
	expected := "Software Engineer"

	tcert, prek0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	key, err := GetKForAttribute("position", prek0, tcert)
	if err != nil {
		t.Error(err)
	}

	encryptedValue, err := EncryptAttributeValuePK0(prek0, "position", []byte(expected))
	if err != nil {
		t.Error(err)
	}

	decryptedValue, err := DecryptAttributeValue(key, encryptedValue)
	if err != nil {
		t.Error(err)
	}

	if string(decryptedValue) != expected {
		t.Errorf("Failed decrypting attribute used calculated key. Expected: %v, Actual: %v", expected, string(decryptedValue))
	}
}

func TestGetKForAttribute_MissingAttribute(t *testing.T) {
	tcert, prek0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	_, err = GetKForAttribute("business_unit", prek0, tcert)
	if err == nil {
		t.Errorf("Trying to get a key for an attribute that is not part of the TCert should produce an error")
	}
}

func TestParseEmptyAttributesHeader(t *testing.T) {
	_, err := ParseAttributesHeader("")
	if err == nil {
		t.Error("Empty header should produce a parsing error")
	}
}

func TestParseAttributesHeader_NotNumberPosition(t *testing.T) {
	_, err := ParseAttributesHeader(headerPrefix + "position->a#")
	if err == nil {
		t.Error("Not number position in the header should produce a parsing error")
	}
}

func TestBuildAndParseAttributesHeader(t *testing.T) {
	attributes := make(map[string]int)
	attributes["company"] = 1
	attributes["position"] = 2

	headerRaw, err := BuildAttributesHeader(attributes)
	if err != nil {
		t.Error(err)
	}
	header := string(headerRaw[:])

	components, err := ParseAttributesHeader(header)
	if err != nil {
		t.Error(err)
	}

	if len(components) != 2 {
		t.Errorf("Error parsing header. Expecting two entries in header, found %v instead", len(components))
	}

	if components["company"] != 1 {
		t.Errorf("Error parsing header. Expected %v with value %v, found %v instead", "company", 1, components["company"])
	}

	if components["position"] != 2 {
		t.Errorf("Error parsing header. Expected %v with value %v, found %v instead", "position", 2, components["position"])
	}
}

func TestReadAttributeHeader(t *testing.T) {
	tcert, prek0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	headerKey := GetAttributeKey(prek0, HeaderAttributeName)

	header, encrypted, err := ReadAttributeHeader(tcert, headerKey)

	if err != nil {
		t.Error(err)
	}

	if !encrypted {
		t.Errorf("Error parsing header. Expecting encrypted header.")
	}

	if len(header) != 1 {
		t.Errorf("Error parsing header. Expecting %v entries in header, found %v instead", 1, len(header))
	}

	if header["position"] != 1 {
		t.Errorf("Error parsing header. Expected %v with value %v, found %v instead", "position", 1, header["position"])
	}
}

func TestReadAttributeHeader_WithoutHeaderKey(t *testing.T) {
	tcert, _, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	_, _, err = ReadAttributeHeader(tcert, nil)

	if err == nil {
		t.Error(err)
	}
}

func TestReadAttributeHeader_InvalidHeaderKey(t *testing.T) {
	tcert, prek0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	headerKey := GetAttributeKey(prek0, HeaderAttributeName+"_invalid")

	_, _, err = ReadAttributeHeader(tcert, headerKey)

	if err == nil {
		t.Error(err)
	}
}

func TestReadTCertAttributeByPosition(t *testing.T) {
	expected := "Software Engineer"

	tcert, prek0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	encryptedAttribute, err := ReadTCertAttributeByPosition(tcert, 1)

	if err != nil {
		t.Error(err)
	}

	attributeKey := GetAttributeKey(prek0, "position")

	attribute, err := DecryptAttributeValue(attributeKey, encryptedAttribute)

	if err != nil {
		t.Error(err)
	}

	if string(attribute) != expected {
		t.Errorf("Failed retrieving attribute value from TCert. Expected: %v, Actual: %v", expected, string(attribute))
	}
}

func TestGetAttributesData(t *testing.T) {
	entries := make([]*pb.AttributesDataEntry, 1)
	var entry pb.AttributesDataEntry
	entry.AttributeName = "position"
	entry.AttributeKey = []byte{0, 0, 0, 0}
	entries[0] = &entry
	attributesData := pb.AttributesData{Entries: entries}
	raw, err := proto.Marshal(&attributesData)
	if err != nil {
		t.Error(err)
	}
	resultData, err := GetAttributesData(raw)
	if err != nil {
		t.Error(err)
	}
	if resultData.Entries[0].AttributeName != attributesData.Entries[0].AttributeName {
		t.Fatalf("Invalid first entry attribute name expected %v result %v", attributesData.Entries[0].AttributeName, resultData.Entries[0].AttributeName)
	}
	if bytes.Compare(resultData.Entries[0].AttributeKey, attributesData.Entries[0].AttributeKey) != 0 {
		t.Fatalf("Invalid first entry attribute key expected %v result %v", attributesData.Entries[0].AttributeKey, resultData.Entries[0].AttributeKey)
	}
}

func TestReadTCertAttributeByPosition_InvalidPositions(t *testing.T) {
	tcert, _, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	_, err = ReadTCertAttributeByPosition(tcert, 2)

	if err == nil {
		t.Error("Test should have failed since there is no attribute in the position 2 of the TCert")
	}

	_, err = ReadTCertAttributeByPosition(tcert, -2)

	if err == nil {
		t.Error("Test should have failed since attribute positions should be positive integer values")
	}
}

func TestCreateAttributesDataObjectFromCert(t *testing.T) {
	tcert, preK0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	attributeKeys := []string{"position"}
	dataObj := CreateAttributesDataObjectFromCert(tcert, preK0, attributeKeys)

	entries := dataObj.GetEntries()
	if len(entries) != 3 {
		t.Errorf("Invalid entries in data result %v but expected %v", len(entries), 3)
	}

	firstEntry := entries[0]
	if firstEntry.AttributeName != "position" {
		t.Errorf("Invalid first attribute name, this has to be %v but is %v", "position", firstEntry.AttributeName)
	}
	firstKey, err := GetKForAttribute("position", preK0, tcert)
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(firstKey, firstEntry.AttributeKey) != 0 {
		t.Errorf("Invalid K for first attribute expected %v but returned %v", firstKey, firstEntry.AttributeKey)
	}
}

func TestCreateAttributesData(t *testing.T) {
	tcert, preK0, err := loadTCertAndPreK0()

	if err != nil {
		t.Error(err)
	}
	tcertRaw := tcert.Raw
	attributeKeys := []string{"position"}
	dataObjRaw, err := CreateAttributesData(tcertRaw, preK0, attributeKeys)
	if err != nil {
		t.Error(err)
	}

	var dataObj pb.AttributesData
	err = proto.Unmarshal(dataObjRaw, &dataObj)
	if err != nil {
		t.Error(err)
	}

	entries := dataObj.GetEntries()
	if len(entries) != 3 {
		t.Errorf("Invalid entries in data result %v but expected %v", len(entries), 3)
	}

	firstEntry := entries[0]
	if firstEntry.AttributeName != "position" {
		t.Errorf("Invalid first attribute name, this has to be %v but is %v", "position", firstEntry.AttributeName)
	}
	firstKey, err := GetKForAttribute("position", preK0, tcert)
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(firstKey, firstEntry.AttributeKey) != 0 {
		t.Errorf("Invalid K for first attribute expected %v but returned %v", firstKey, firstEntry.AttributeKey)
	}
}

func TestCreateAttributesData_AttributeNotFound(t *testing.T) {
	tcert, preK0, err := loadTCertAndPreK0()

	if err != nil {
		t.Error(err)
	}
	tcertRaw := tcert.Raw
	attributeKeys := []string{"company"}
	dataObjRaw, err := CreateAttributesData(tcertRaw, preK0, attributeKeys)
	if err != nil {
		t.Error(err)
	}

	var dataObj pb.AttributesData
	err = proto.Unmarshal(dataObjRaw, &dataObj)
	if err != nil {
		t.Error(err)
	}
	entries := dataObj.GetEntries()
	if len(entries) != 3 {
		t.Errorf("Invalid entries in data result %v but expected %v", len(entries), 3)
	}

	firstEntry := entries[0]
	if firstEntry.AttributeName != "company" {
		t.Errorf("Invalid first attribute name, this has to be %v but is %v", "position", firstEntry.AttributeName)
	}
	_, err = GetKForAttribute("company", preK0, tcert)
	if err == nil {
		t.Fatalf("Test should faild because company is not included within the TCert.")
	}
}

func TestCreateAttributesData_InvalidCertificate(t *testing.T) {
	tcert, preK0, err := loadTCertAndPreK0()

	if err != nil {
		t.Error(err)
	}
	tcertRaw := tcert.Raw

	//Became corrupt the certificate.
	tcertRaw[0] = tcertRaw[0] + 124
	attributeKeys := []string{"company"}
	_, err = CreateAttributesData(tcertRaw, preK0, attributeKeys)
	if err == nil {
		t.Fatalf("Failed error expected because certificate is corrupt.")
	}
}

func TestCreateAttributesDataObjectFromCert_AttributeEmptyName(t *testing.T) {
	tcert, preK0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	attributeKeys := []string{""}
	dataObj := CreateAttributesDataObjectFromCert(tcert, preK0, attributeKeys)

	entries := dataObj.GetEntries()
	if len(entries) != 2 {
		t.Errorf("Invalid entries in data result %v but expected %v", len(entries), 1)
	}
}

func TestCreateAttributesDataObjectFromCert_AttributeNotFound(t *testing.T) {
	tcert, preK0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	attributeKeys := []string{"company"}
	dataObj := CreateAttributesDataObjectFromCert(tcert, preK0, attributeKeys)

	entries := dataObj.GetEntries()
	if len(entries) != 3 {
		t.Errorf("Invalid entries in data result %v but expected %v", len(entries), 3)
	}

	firstEntry := entries[0]
	if firstEntry.AttributeName != "company" {
		t.Errorf("Invalid first attribute name, this has to be %v but is %v", "position", firstEntry.AttributeName)
	}
	_, err = GetKForAttribute("company", preK0, tcert)
	if err == nil {
		t.Fatalf("Test should failed because company is not included within the TCert.")
	}
}

func TestCreateAttributesDataFromKeys(t *testing.T) {
	_, preK0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	positionKey := GetAttributeKey(preK0, "position")
	headerKey := GetAttributeKey(preK0, HeaderAttributeName)
	attributeKey := append(headerKey, positionKey...)
	attributesData, err := CreateAttributesDataFromKeys([]string{"position"}, [][]byte{attributeKey})
	if err != nil {
		t.Error(err)
	}
	if len(attributesData.GetEntries()) != 2 {
		t.Errorf("Test failed expected 2 entries (header and position) but returned [%v]", len(attributesData.GetEntries()))
	}
}

func TestCreateAttributesDataFromKeys_NilAttributesNames(t *testing.T) {
	_, preK0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	positionKey := GetAttributeKey(preK0, "position")
	headerKey := GetAttributeKey(preK0, HeaderAttributeName)
	attributeKey := append(headerKey, positionKey...)
	_, err = CreateAttributesDataFromKeys(nil, [][]byte{attributeKey})
	if err == nil {
		t.Fatalf("Test should failed because attributes names is nil.")
	}

}

func TestCreateAttributesDataFromKeys_NilAttributesKeys(t *testing.T) {
	_, err := CreateAttributesDataFromKeys([]string{"position"}, nil)
	if err == nil {
		t.Fatalf("Test should failed because attributes names is nil.")
	}

}

func TestCreateAttributesDataFromKeys_EmptyAttributesNames(t *testing.T) {
	_, preK0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	positionKey := GetAttributeKey(preK0, "position")
	headerKey := GetAttributeKey(preK0, HeaderAttributeName)
	attributeKey := append(headerKey, positionKey...)
	_, err = CreateAttributesDataFromKeys([]string{}, [][]byte{attributeKey})
	if err == nil {
		t.Fatalf("Test should failed because attributes names is nil.")
	}

}

func TestCreateAttributesDataFromKeys_EmptyAttributesKeys(t *testing.T) {
	_, err := CreateAttributesDataFromKeys([]string{"position"}, [][]byte{})
	if err == nil {
		t.Fatalf("Test should failed because attributes names is nil.")
	}

}

func TestCreateAttributesDataFromKeys_NoreNamesThanKeys(t *testing.T) {
	_, preK0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	positionKey := GetAttributeKey(preK0, "position")
	headerKey := GetAttributeKey(preK0, HeaderAttributeName)
	attributeKey := append(headerKey, positionKey...)
	_, err = CreateAttributesDataFromKeys([]string{"position", "age"}, [][]byte{attributeKey})
	if err == nil {
		t.Fatalf("Test should failed because there are most attributes names than attributes keys.")
	}

}

func TestCreateAttributesDataFromKeys_ShortKey(t *testing.T) {
	_, preK0, err := loadTCertAndPreK0()
	if err != nil {
		t.Error(err)
	}

	positionKey := GetAttributeKey(preK0, "position")
	_, err = CreateAttributesDataFromKeys([]string{"position"}, [][]byte{positionKey})
	if err == nil {
		t.Fatalf("Test should failed because key is less than 64 bytes.")
	}

}

func TestBuildAttributesHeader(t *testing.T) {
	attributes := make(map[string]int)
	attributes["company"] = 0
	attributes["position"] = 1
	attributes["country"] = 2
	result, err := BuildAttributesHeader(attributes)
	if err != nil {
		t.Error(err)
	}

	resultStr := string(result)

	if !strings.HasPrefix(resultStr, headerPrefix) {
		t.Fatalf("Invalid header prefix expected %v result %v", headerPrefix, resultStr)
	}

	if !strings.Contains(resultStr, "company->0#") {
		t.Fatalf("Invalid header shoud include '%v'", "company->0#")
	}

	if !strings.Contains(resultStr, "position->1#") {
		t.Fatalf("Invalid header shoud include '%v'", "position->1#")
	}

	if !strings.Contains(resultStr, "country->2#") {
		t.Fatalf("Invalid header shoud include '%v'", "country->2#")
	}
}

func TestBuildAttributesHeader_DuplicatedPosition(t *testing.T) {
	attributes := make(map[string]int)
	attributes["company"] = 0
	attributes["position"] = 0
	attributes["country"] = 1
	_, err := BuildAttributesHeader(attributes)
	if err == nil {
		t.Fatalf("Error this tests should fail because header has two attributes with the same position")
	}
}

func loadTCertAndPreK0() (*x509.Certificate, []byte, error) {
	preKey0, err := ioutil.ReadFile("./test_resources/prek0.dump")
	if err != nil {
		return nil, nil, err
	}

	if err != nil {
		return nil, nil, err
	}

	tcertRaw, err := ioutil.ReadFile("./test_resources/tcert.dump")
	if err != nil {
		return nil, nil, err
	}

	tcertDecoded, _ := pem.Decode(tcertRaw)

	tcert, err := x509.ParseCertificate(tcertDecoded.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return tcert, preKey0, nil
}
