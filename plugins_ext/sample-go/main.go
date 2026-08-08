package main

import (
	"encoding/json"
	"github.com/extism/go-pdk"
)

type ScanContext struct {
	Target string `json:"target"`
}

type Finding struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

//export run_scan
func run_scan() int32 {
	input := pdk.Input()
	var ctx ScanContext
	json.Unmarshal(input, &ctx)

	findings := []Finding{
		{
			Title:       "Sample Finding",
			Severity:    "INFO",
			Description: "Scanned target: " + ctx.Target,
		},
	}

	output, _ := json.Marshal(findings)
	pdk.Output(output)
	return 0
}

func main() {}
