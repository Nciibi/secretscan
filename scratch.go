package main

import (
	"fmt"
	"github.com/secretscan/secretscan/internal/detectors"
)

func main() {
	d := detectors.NewTwilioSIDDetector()
	line := "export TWILIO_ACCOUNT_SID=AC11111111111111111111111111111111"
	findings := d.Detect(line, 1, "test.txt")
	if len(findings) > 0 {
		fmt.Printf("Confidence: %d\n", findings[0].Confidence)
		fmt.Printf("Reason: %s\n", findings[0].Reason)
	} else {
		fmt.Println("No findings")
	}
}
