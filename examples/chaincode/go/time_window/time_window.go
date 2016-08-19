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

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

//n = number of bits used as offset within a time window.
var n = 10

//Window Mask
var wm = []byte{255, 255, 255, 255, 255, 255, 252, 0}

//Shift array
var shift = []uint{56, 48, 40, 32, 24, 16, 8, 0}

// World state time window key
var timeWindow = "time-window"

//TimeWindowChaincode is the chaincode used to calculates the TimeWindow
type TimeWindowChaincode struct {
}

//Init initializes the TimeWindow chaincode.
func (t *TimeWindowChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	return nil, nil
}

func (t *TimeWindowChaincode) toBytes(ts int64) (bs []byte, err error) {
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, ts)
	bs = buf.Bytes()
	return
}

func (t *TimeWindowChaincode) getTW(ts []byte) (tw []byte) {
	tw = []byte{0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 8; i++ {
		tw[i] = wm[i] & ts[i]
	}
	return
}

//Invoke is used to update the TimeWindow
func (t *TimeWindowChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if function != "update" {
		return nil, errors.New("Invalid invoke function name. Expecting \"update\"")
	}
	currentTime := time.Now().Unix()
	ts, err := t.toBytes(currentTime)
	if err != nil {
		return nil, err
	}
	tw := t.getTW(ts)
	oldTw, err := stub.GetState(timeWindow)
	if oldTw != nil {
		d, err := t.distance(tw, oldTw)
		if err != nil {
			return nil, err
		}

		fmt.Printf("TW:  ")
		for i := 0; i < 8; i++ {
			fmt.Printf("%v ", int(tw[i]))
		}
		fmt.Printf("\n")

		fmt.Printf("OTW: ")
		for i := 0; i < 8; i++ {
			fmt.Printf("%v ", int(oldTw[i]))
		}
		fmt.Printf("\n")

		fmt.Printf("Difference = %v\n", d)
		if d > 1 {
			tw = oldTw
			for i := 7; i > 0; i-- {
				if tw[i] < 255 {
					tw[i] = tw[i] + 1
					break
				} else {
					tw[i] = 0
				}
			}
		}
	}
	stub.PutState(timeWindow, tw)
	return nil, nil
}

func (t *TimeWindowChaincode) distance(a, b []byte) (d int64, err error) {
	l := len(a)
	if l != len(b) || l != 8 {
		return 0, errors.New("Is not supported calculate the distance between values of different length.")
	}
	var delta int64
	for i := 0; i < 7; i++ {
		delta = int64(a[i]) - int64(b[i])
		delta = delta << shift[i+1]
		d = d + delta
	}
	return
}

//Query returns the current value of timeWindow
func (t *TimeWindowChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if function != "read" {
		return nil, errors.New("Invalid query function name. Expecting \"read\"")
	}
	var err error

	// Get the state from the ledger
	tw, err := stub.GetState(timeWindow)
	if err != nil {
		jsonResp := "{\"Error\":\"Failed to get state for \"" + timeWindow + "\"}"
		return nil, errors.New(jsonResp)
	}

	currentTime := time.Now().Unix()
	ts, err := t.toBytes(currentTime)
	if err != nil {
		return nil, err
	}
	fmt.Printf("TS: ")
	for i := 0; i < 8; i++ {
		fmt.Printf("%v ", int(ts[i]))
	}
	fmt.Printf("\n")
	fmt.Printf("TW: ")
	for i := 0; i < 8; i++ {
		fmt.Printf("%v ", int(tw[i]))
	}
	fmt.Printf("\n")
	return tw, nil
}

func main() {
	err := shim.Start(new(TimeWindowChaincode))
	if err != nil {
		fmt.Printf("Error starting TimeWindow chaincode: %s", err)
	}
}
