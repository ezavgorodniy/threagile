package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"

	"github.com/threagile/threagile/pkg/model"
)

// JUST A DUMMY TO HAVE AN ALTERNATIVE PLUGIN TO USE/TEST

func main() {
	reader := bufio.NewReader(os.Stdin)

	inData, outError := io.ReadAll(reader)
	if outError != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to read model data from stdin\n")
		os.Exit(-2)
	}

	var input model.ParsedModel
	inError := json.Unmarshal(inData, &input)
	if inError != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to parse model: %v\n", inError)
		os.Exit(-2)
	}

	text := CalculateRAA(&input)
	outData, marshalError := json.Marshal(input)
	if marshalError != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to print model: %v\n", marshalError)
		os.Exit(-2)
	}

	_, _ = fmt.Fprint(os.Stdout, outData)
	_, _ = fmt.Fprint(os.Stderr, text)
	os.Exit(0)
}

// used from run caller:

func CalculateRAA(input *model.ParsedModel) string {
	for techAssetID, techAsset := range input.TechnicalAssets {
		techAsset.RAA = float64(rand.Intn(100))
		fmt.Println("Using dummy RAA random calculation (just to test the usage of other shared object files as plugins)")
		input.TechnicalAssets[techAssetID] = techAsset
	}
	// return intro text (for reporting etc., can be short summary-like)
	return "Just some dummy algorithm implementation for demo purposes of pluggability..."
}
