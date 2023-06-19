package scanner

import (
	http "net/http"
	"strings"
	"testing"
)

type TestAvast struct {
	Engine
}

func TestAvast_callAvastRestApi(t *testing.T) {
	// Given
	avast := new(Avast)
	avast.SetAddress("http://localhost:9090")
	reader := strings.NewReader("my request")

	// When
	scanResponse, err := avast.callAvastRestApi(reader)

	// Then
	if scanResponse == nil || err != nil {
		t.Errorf("expected a response and no error\nerror: %s\nscanResponse: %s", err, scanResponse)
	}
}

func TestAvast_shouldUnmarshalResponseGivenNoIssues(t *testing.T) {
	// Given
	avast := new(Avast)
	vpsVersion := "1234567890"
	responseBody := "{ \"vps_version\": \"" + vpsVersion + "\"}"

	// When
	scanResponse, err := avast.unmarshalResponse([]byte(responseBody))

	// Then
	if err != nil {
		t.Errorf("expected no error %s", err)
	}
	if len(scanResponse.Issues) != 0 {
		t.Errorf("expected no issues found %d", len(scanResponse.Issues))
	}
	if scanResponse.VpsVersion != vpsVersion {
		t.Errorf("expected vpsVersion 1234567890 found %s", scanResponse.VpsVersion)
	}
}

func TestAvast_shouldUnmarshalResponseGivenIssues(t *testing.T) {
	// Given
	avast := new(Avast)
	responseBody := `
{
  "issues": [
    {
      "path": [
        "/path/to/archive.zip",
        "test/eicar.txt"
      ],
      "virus": "EICAR Test-NOT virus!!!",
      "detections": [
        {
          "virus": "EICAR Test-NOT virus!!!",
          "algo": "troj",
          "aux": "PE3-C669AF050002E7759F732D603981C3F0"
        }
      ],
      "warning_id": 42110,
      "warning_str": "The file is a decompression bomb"
    }
  ],
  "vpsVersion": "21091404"
}`

	// When
	scanResponse, err := avast.unmarshalResponse([]byte(responseBody))

	// Then
	if err != nil {
		t.Errorf("expected no error %s", err)
	}
	if len(scanResponse.Issues) != 1 {
		t.Errorf("expected 1 issue found %d", len(scanResponse.Issues))
	}
}

func TestBanana(t *testing.T) {
	resp, err := http.Get("https://google.co.uk")
	if err != nil {
		t.Errorf("err %s", err)
	}
	if resp == nil {
		t.Errorf("resp")
	}
}
