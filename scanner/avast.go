package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

/*
 * Avast scans files using Avast
 */
type Avast struct {
	Engine
	//clam *clamd.Clamd
	//url string
}

func (avast *Avast) SetAddress(url string) {
	avast.Engine.SetAddress(url)
	//	avast.logger.Println("Initialised Avast connection to", url)
}

// HasVirus
//
//	curl -X 'POST' --header 'accept: application/json' --header 'Content-Type: application/octet-stream' --data-binary '@data.json' localhost:9090/v1/scan?filename=data.json&email=false&full=false&archives=true&pup=false&heuristics=80&detections=false
func (avast *Avast) HasVirus(reader io.Reader) (bool, error) {
	response, err := avast.callAvastRestApi(reader)
	if err != nil {
		return false, err
	}
	return response.hasIssues(), nil
}

func (avast *Avast) Scan(reader io.Reader) (*Result, error) {
	response, err := avast.callAvastRestApi(reader)
	if err != nil {
		return nil, err
	}
	status := getStatus(response)
	result := &Result{
		Status:      status,
		Virus:       status == RES_FOUND,
		Description: "No virus found",
	}
	return result, nil
}

func getStatus(response *ScanResponse) string {
	var status string
	if response.hasIssues() {
		status = RES_CLEAN
	} else {
		status = RES_FOUND
	}
	return status
}

func (avast *Avast) callAvastRestApi(reader io.Reader) (*ScanResponse, error) {
	avastRestResponse, err := http.Post(avast.address+"/v1/scan", "application/octet-stream", reader)
	if err != nil {
		return nil, errors.New("Failed to post scan to avast: " + err.Error())
	}
	if avastRestResponse.StatusCode != 200 {
		return nil, errors.New("Avast replied with non 200 OK status: " + avastRestResponse.Status)
	}
	rawBody, err := io.ReadAll(avastRestResponse.Body)
	if err != nil {
		return nil, errors.New("Failed to read body: " + err.Error())
	}
	response, err := avast.unmarshalResponse(rawBody)
	if err != nil {
		return nil, errors.New("Failed to unmarshall response: " + err.Error())
	}
	return response, nil
}

func (avast *Avast) Ping() error {
	// TODO http request to "/" and look for a 404
	/*
		james.kennard@lw-preprodnet-edge-1:~$ curl -v localhost:9090
		*   Trying 127.0.0.1:9090...
		* TCP_NODELAY set
		* Connected to localhost (127.0.0.1) port 9090 (#0)
		> GET / HTTP/1.1
		> Host: localhost:9090
		> User-Agent: curl/7.68.0
		> Accept: *\/*
		>
			* Mark bundle as not supporting multiuse
		< HTTP/1.1 404 Not Found
		< Server: avast-rest/4.3.1
		< Content-Type: text/html
		< Content-Length: 32
		<
		The resource '/' was not found.
		* Connection #0 to host localhost left intact

	*/
	return nil
}

func (avast *Avast) Version() (string, error) {
	return "nil", nil
	//ch, err := c.clam.Version()
	//if err != nil {
	//	return "", err
	//}
	//
	//r := (<-ch)
	//return r.Raw, nil
}

func (avast *Avast) unmarshalResponse(responseBody []byte) (*ScanResponse, error) {
	var scanResponse *ScanResponse
	err := json.Unmarshal(responseBody, &scanResponse)
	if err != nil {
		fmt.Printf("could not unmarshal json: %s\n", err)
		return nil, err
	}
	return scanResponse, nil
}

type ScanResponse struct {
	Issues []ScanRecord `json:"issues"`
	// Version of VPS (virus database) that was used to scan the file.
	VpsVersion string `json:"vps_version"`
}

type ScanRecord struct {
	//// Infected paths. The first part is the path or filename as given in the request. Each other part is a path inside an archive. Multiple archive paths are possible in case of wrapped archives.
	//Path []string `json:"path"`
	//// A name of a virus found in the path. This string is a unique ID of the virus.
	//Virus *string `json:"virus,omitempty"`
	//// Verbose information about all virus detections found in the path. When enabled in config or by query parameter, this replaces the single `virus` field by an array, where detections[0].virus is the reported virus and further items may contain additional detections. This is useful mainly for investigating problems with the scanner (e.g. false positives).
	//Detections []VirusDetection `json:"detections,omitempty"`
	//// Unique warning ID. Warnings are generated for other (non-virus) issues.
	//WarningId *int32 `json:"warning_id,omitempty"`
	//// Textual description of the warning.
	//WarningStr *string `json:"warning_str,omitempty"`
}

//type VirusDetection struct {
//	// A name of a virus found in the path. This string is a unique ID of the virus.
//	Virus string `json:"virus"`
//	// Detection algorithm that found the virus.
//	Algo *string `json:"algo,omitempty"`
//	// Auxiliary information about the detection.
//	Aux *string `json:"aux,omitempty"`
//}

func (response *ScanResponse) hasIssues() bool {
	return len(response.Issues) > 0
}
