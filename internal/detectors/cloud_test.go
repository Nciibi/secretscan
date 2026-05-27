package detectors

import (
	"testing"
)

func TestCloudDetectors(t *testing.T) {
	tests := []struct {
		name     string
		detector Detector
		tps      []string
		tns      []string
	}{
		{
			name:     "AzureSAS",
			detector: NewAzureSASDetector(),
			tps: []string{
				`sig=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu`,
				`BlobEndpoint=https://account.blob.core.windows.net/;SharedAccessSignature=sv=2020-02-10&ss=b&srt=co&sp=rwdlac&se=2021-01-31T20:25:22Z&st=2021-01-31T12:25:22Z&spr=https&sig=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu`,
				`url="https://example.com/blob?sig=1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHI"`,
			},
			tns: []string{
				`sig=placeholder_signature_do_not_use`,
				`sig=your_signature_here`,
				`sig=xxx`,
			},
		},
		{
			name:     "AzureConnectionString",
			detector: NewAzureConnectionStringDetector(),
			tps: []string{
				`DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123def456ghi789jkl012mno345pqr678stu901vwx234=`,
				`azure_conn="DefaultEndpointsProtocol=https;AccountName=test;AccountKey=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv="`,
				`DefaultEndpointsProtocol=https;AccountName=prod;AccountKey=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk=`,
			},
			tns: []string{
				`DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=your_key_here`,
				`DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=placeholder`,
				`DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=xxx`,
			},
		},
		{
			name:     "GCPServiceAccount",
			detector: NewGCPServiceAccountDetector(),
			tps: []string{
				`"type": "service_account"`,
				`{"type": "service_account", "project_id": "test"}`,
				`  "type": "service_account",`,
			},
			tns: []string{
				`"type": "user"`,
				`"type": "something_else"`,
				`type: service_account`, // missing quotes
			},
		},
		{
			name:     "GCPAPIKey",
			detector: NewGCPAPIKeyDetector(),
			tps: []string{
				`AIzaSyA_BcdEfGhIjKlMnOpQrStUvWxYz123456`,
				`gcp_key = "AIzaSyA-BcdEfGhIjKlMnOpQrStUvWxYz123456"`,
				`export API_KEY=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567`,
			},
			tns: []string{
				`AIzaSyYOUR_API_KEY_HERE_REPLACE_ME_NOW`,
				`AIzaSy_placeholder_key_for_example_only`,
				`AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("True Positives", func(t *testing.T) {
				for _, tc := range tt.tps {
					filePath := "test.txt"
					if tt.name == "GCPServiceAccount" {
						filePath = "key.json" // GCPServiceAccount checks extension
					}
					findings := tt.detector.Detect(tc, 1, filePath)
					if len(findings) == 0 {
						t.Errorf("Expected finding for %s, got none", tc)
						continue
					}
					if findings[0].Confidence < 50 {
						t.Errorf("Expected confidence >= 50 for %s, got %d", tc, findings[0].Confidence)
					}
				}
			})

			t.Run("True Negatives", func(t *testing.T) {
				for _, tc := range tt.tns {
					filePath := "test.txt"
					if tt.name == "GCPServiceAccount" {
						filePath = "key.json"
					}
					findings := tt.detector.Detect(tc, 1, filePath)
					for _, f := range findings {
						if f.Confidence >= 25 {
							t.Errorf("Expected confidence < 25 for %s, got %d", tc, f.Confidence)
						}
					}
				}
			})
		})
	}
}
