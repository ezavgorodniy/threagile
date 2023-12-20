/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package pkg

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt" // TODO: no fmt here
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"

	"github.com/akedrou/textdiff"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/threagile/threagile/pkg/colors"
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/run"
	"github.com/threagile/threagile/pkg/security/types"

	addbuildpipeline "github.com/threagile/threagile/pkg/macros/built-in/add-build-pipeline"
	addvault "github.com/threagile/threagile/pkg/macros/built-in/add-vault"
	prettyprint "github.com/threagile/threagile/pkg/macros/built-in/pretty-print"
	removeunusedtags "github.com/threagile/threagile/pkg/macros/built-in/remove-unused-tags"
	seedrisktracking "github.com/threagile/threagile/pkg/macros/built-in/seed-risk-tracking"
	seedtags "github.com/threagile/threagile/pkg/macros/built-in/seed-tags"

	accidentalsecretleak "github.com/threagile/threagile/pkg/security/risks/built-in/accidental-secret-leak"
	codebackdooring "github.com/threagile/threagile/pkg/security/risks/built-in/code-backdooring"
	containerbaseimagebackdooring "github.com/threagile/threagile/pkg/security/risks/built-in/container-baseimage-backdooring"
	containerplatformescape "github.com/threagile/threagile/pkg/security/risks/built-in/container-platform-escape"
	crosssiterequestforgery "github.com/threagile/threagile/pkg/security/risks/built-in/cross-site-request-forgery"
	crosssitescripting "github.com/threagile/threagile/pkg/security/risks/built-in/cross-site-scripting"
	dosriskyaccessacrosstrustboundary "github.com/threagile/threagile/pkg/security/risks/built-in/dos-risky-access-across-trust-boundary"
	incompletemodel "github.com/threagile/threagile/pkg/security/risks/built-in/incomplete-model"
	ldapinjection "github.com/threagile/threagile/pkg/security/risks/built-in/ldap-injection"
	missingauthentication "github.com/threagile/threagile/pkg/security/risks/built-in/missing-authentication"
	missingauthenticationsecondfactor "github.com/threagile/threagile/pkg/security/risks/built-in/missing-authentication-second-factor"
	missingbuildinfrastructure "github.com/threagile/threagile/pkg/security/risks/built-in/missing-build-infrastructure"
	missingcloudhardening "github.com/threagile/threagile/pkg/security/risks/built-in/missing-cloud-hardening"
	missingfilevalidation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-file-validation"
	missinghardening "github.com/threagile/threagile/pkg/security/risks/built-in/missing-hardening"
	missingidentitypropagation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-identity-propagation"
	missingidentityproviderisolation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-identity-provider-isolation"
	missingidentitystore "github.com/threagile/threagile/pkg/security/risks/built-in/missing-identity-store"
	missingnetworksegmentation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-network-segmentation"
	missingvault "github.com/threagile/threagile/pkg/security/risks/built-in/missing-vault"
	missingvaultisolation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-vault-isolation"
	missingwaf "github.com/threagile/threagile/pkg/security/risks/built-in/missing-waf"
	mixedtargetsonsharedruntime "github.com/threagile/threagile/pkg/security/risks/built-in/mixed-targets-on-shared-runtime"
	pathtraversal "github.com/threagile/threagile/pkg/security/risks/built-in/path-traversal"
	pushinsteadofpulldeployment "github.com/threagile/threagile/pkg/security/risks/built-in/push-instead-of-pull-deployment"
	searchqueryinjection "github.com/threagile/threagile/pkg/security/risks/built-in/search-query-injection"
	serversiderequestforgery "github.com/threagile/threagile/pkg/security/risks/built-in/server-side-request-forgery"
	serviceregistrypoisoning "github.com/threagile/threagile/pkg/security/risks/built-in/service-registry-poisoning"
	sqlnosqlinjection "github.com/threagile/threagile/pkg/security/risks/built-in/sql-nosql-injection"
	uncheckeddeployment "github.com/threagile/threagile/pkg/security/risks/built-in/unchecked-deployment"
	unencryptedasset "github.com/threagile/threagile/pkg/security/risks/built-in/unencrypted-asset"
	unencryptedcommunication "github.com/threagile/threagile/pkg/security/risks/built-in/unencrypted-communication"
	unguardedaccessfrominternet "github.com/threagile/threagile/pkg/security/risks/built-in/unguarded-access-from-internet"
	unguardeddirectdatastoreaccess "github.com/threagile/threagile/pkg/security/risks/built-in/unguarded-direct-datastore-access"
	unnecessarycommunicationlink "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-communication-link"
	unnecessarydataasset "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-data-asset"
	unnecessarydatatransfer "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-data-transfer"
	unnecessarytechnicalasset "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-technical-asset"
	untrusteddeserialization "github.com/threagile/threagile/pkg/security/risks/built-in/untrusted-deserialization"
	wrongcommunicationlinkcontent "github.com/threagile/threagile/pkg/security/risks/built-in/wrong-communication-link-content"
	wrongtrustboundarycontent "github.com/threagile/threagile/pkg/security/risks/built-in/wrong-trust-boundary-content"
	xmlexternalentity "github.com/threagile/threagile/pkg/security/risks/built-in/xml-external-entity"
)

type Context struct {
	ServerMode bool

	successCount                                                 int
	errorCount                                                   int
	drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks bool
	buildTimestamp                                               string

	globalLock sync.Mutex
	modelInput input.ModelInput

	// TODO: remove refactoring note below
	// moved from types.go
	parsedModel model.ParsedModel

	modelFilename, templateFilename                                                                   *string
	testParseModel                                                                                    *bool
	createExampleModel, createStubModel, createEditingSupport, verbose, ignoreOrphanedRiskTracking    *bool
	generateDataFlowDiagram, generateDataAssetDiagram, generateRisksJSON, generateTechnicalAssetsJSON *bool
	generateStatsJSON, generateRisksExcel, generateTagsExcel, generateReportPDF                       *bool
	outputDir, raaPlugin, skipRiskRules, riskRulesPlugins, executeModelMacro                          *string
	customRiskRules                                                                                   map[string]*model.CustomRisk
	diagramDPI, serverPort                                                                            *int
	deferredRiskTrackingDueToWildcardMatching                                                         map[string]model.RiskTracking
	addModelTitle                                                                                     bool
	keepDiagramSourceFiles                                                                            bool
	appFolder                                                                                         *string
	binFolder                                                                                         *string
	serverFolder                                                                                      *string
	tempFolder                                                                                        *string

	defaultGraphvizDPI       int
	maxGraphvizDPI           int
	backupHistoryFilesToKeep int

	tempDir                                string
	binDir                                 string
	appDir                                 string
	dataDir                                string
	keyDir                                 string
	reportFilename                         string
	excelRisksFilename                     string
	excelTagsFilename                      string
	jsonRisksFilename                      string
	jsonTechnicalAssetsFilename            string
	jsonStatsFilename                      string
	dataFlowDiagramFilenameDOT             string
	dataFlowDiagramFilenamePNG             string
	dataAssetDiagramFilenameDOT            string
	dataAssetDiagramFilenamePNG            string
	graphvizDataFlowDiagramConversionCall  string
	graphvizDataAssetDiagramConversionCall string
	inputFile                              string
}

func (context *Context) addToListOfSupportedTags(tags []string) {
	for _, tag := range tags {
		context.parsedModel.AllSupportedTags[tag] = true
	}
}

func (context *Context) checkRiskTracking() {
	if *context.verbose {
		fmt.Println("Checking risk tracking")
	}
	for _, tracking := range context.parsedModel.RiskTracking {
		if _, ok := context.parsedModel.GeneratedRisksBySyntheticId[tracking.SyntheticRiskId]; !ok {
			if *context.ignoreOrphanedRiskTracking {
				fmt.Println("Risk tracking references unknown risk (risk id not found): " + tracking.SyntheticRiskId)
			} else {
				panic(errors.New("Risk tracking references unknown risk (risk id not found) - you might want to use the option -ignore-orphaned-risk-tracking: " + tracking.SyntheticRiskId +
					"\n\nNOTE: For risk tracking each risk-id needs to be defined (the string with the @ sign in it). " +
					"These unique risk IDs are visible in the PDF report (the small grey string under each risk), " +
					"the Excel (column \"ID\"), as well as the JSON responses. Some risk IDs have only one @ sign in them, " +
					"while others multiple. The idea is to allow for unique but still speaking IDs. Therefore each risk instance " +
					"creates its individual ID by taking all affected elements causing the risk to be within an @-delimited part. " +
					"Using wildcards (the * sign) for parts delimited by @ signs allows to handle groups of certain risks at once. " +
					"Best is to lookup the IDs to use in the created Excel file. Alternatively a model macro \"seed-risk-tracking\" " +
					"is available that helps in initially seeding the risk tracking part here based on already identified and not yet handled risks."))
			}
		}
	}

	// save also the risk-category-id and risk-status directly in the risk for better JSON marshalling
	for category := range context.parsedModel.GeneratedRisksByCategory {
		for i := range context.parsedModel.GeneratedRisksByCategory[category] {
			context.parsedModel.GeneratedRisksByCategory[category][i].CategoryId = category.Id
			context.parsedModel.GeneratedRisksByCategory[category][i].RiskStatus = context.parsedModel.GeneratedRisksByCategory[category][i].GetRiskTrackingStatusDefaultingUnchecked(&context.parsedModel)
		}
	}
}

func (context *Context) Defaults(buildTimestamp string) *Context {
	*context = Context{
		keepDiagramSourceFiles: false,
		addModelTitle:          false,
		buildTimestamp:         buildTimestamp,
		customRiskRules:        make(map[string]*model.CustomRisk),
		deferredRiskTrackingDueToWildcardMatching:                    make(map[string]model.RiskTracking),
		drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks: true,
		defaultGraphvizDPI:       120,
		maxGraphvizDPI:           240,
		backupHistoryFilesToKeep: 50,
	}

	context.tempDir = "/dev/shm" // TODO: make configurable via cmdline arg?
	context.binDir = "/app"
	context.appDir = "/app"
	context.dataDir = "/data"
	context.keyDir = "keys"
	context.reportFilename = "report.pdf"
	context.excelRisksFilename = "risks.xlsx"
	context.excelTagsFilename = "tags.xlsx"
	context.jsonRisksFilename = "risks.json"
	context.jsonTechnicalAssetsFilename = "technical-assets.json"
	context.jsonStatsFilename = "stats.json"
	context.dataFlowDiagramFilenameDOT = "data-flow-diagram.gv"
	context.dataFlowDiagramFilenamePNG = "data-flow-diagram.png"
	context.dataAssetDiagramFilenameDOT = "data-asset-diagram.gv"
	context.dataAssetDiagramFilenamePNG = "data-asset-diagram.png"
	context.graphvizDataFlowDiagramConversionCall = "render-data-flow-diagram.sh"
	context.graphvizDataAssetDiagramConversionCall = "render-data-asset-diagram.sh"
	context.inputFile = "threagile.yaml"

	return context
}

func (context *Context) applyRisk(rule model.CustomRiskRule, skippedRules *map[string]bool) {
	id := rule.Category().Id
	_, ok := (*skippedRules)[id]

	if ok {
		fmt.Printf("Skipping risk rule %q\n", rule.Category().Id)
		delete(*skippedRules, rule.Category().Id)
	} else {
		context.addToListOfSupportedTags(rule.SupportedTags())
		generatedRisks := rule.GenerateRisks(&context.parsedModel)
		if generatedRisks != nil {
			if len(generatedRisks) > 0 {
				context.parsedModel.GeneratedRisksByCategory[rule.Category()] = generatedRisks
			}
		} else {
			fmt.Printf("Failed to generate risks for %q\n", id)
		}
	}
}

func (context *Context) applyRiskGeneration() {
	if *context.verbose {
		fmt.Println("Applying risk generation")
	}

	skippedRules := make(map[string]bool)
	if len(*context.skipRiskRules) > 0 {
		for _, id := range strings.Split(*context.skipRiskRules, ",") {
			skippedRules[id] = true
		}
	}

	context.applyRisk(accidentalsecretleak.Rule(), &skippedRules)
	context.applyRisk(codebackdooring.Rule(), &skippedRules)
	context.applyRisk(containerbaseimagebackdooring.Rule(), &skippedRules)
	context.applyRisk(containerplatformescape.Rule(), &skippedRules)
	context.applyRisk(crosssiterequestforgery.Rule(), &skippedRules)
	context.applyRisk(crosssitescripting.Rule(), &skippedRules)
	context.applyRisk(dosriskyaccessacrosstrustboundary.Rule(), &skippedRules)
	context.applyRisk(incompletemodel.Rule(), &skippedRules)
	context.applyRisk(ldapinjection.Rule(), &skippedRules)
	context.applyRisk(missingauthentication.Rule(), &skippedRules)
	context.applyRisk(missingauthenticationsecondfactor.Rule(), &skippedRules)
	context.applyRisk(missingbuildinfrastructure.Rule(), &skippedRules)
	context.applyRisk(missingcloudhardening.Rule(), &skippedRules)
	context.applyRisk(missingfilevalidation.Rule(), &skippedRules)
	context.applyRisk(missinghardening.Rule(), &skippedRules)
	context.applyRisk(missingidentitypropagation.Rule(), &skippedRules)
	context.applyRisk(missingidentityproviderisolation.Rule(), &skippedRules)
	context.applyRisk(missingidentitystore.Rule(), &skippedRules)
	context.applyRisk(missingnetworksegmentation.Rule(), &skippedRules)
	context.applyRisk(missingvault.Rule(), &skippedRules)
	context.applyRisk(missingvaultisolation.Rule(), &skippedRules)
	context.applyRisk(missingwaf.Rule(), &skippedRules)
	context.applyRisk(mixedtargetsonsharedruntime.Rule(), &skippedRules)
	context.applyRisk(pathtraversal.Rule(), &skippedRules)
	context.applyRisk(pushinsteadofpulldeployment.Rule(), &skippedRules)
	context.applyRisk(searchqueryinjection.Rule(), &skippedRules)
	context.applyRisk(serversiderequestforgery.Rule(), &skippedRules)
	context.applyRisk(serviceregistrypoisoning.Rule(), &skippedRules)
	context.applyRisk(sqlnosqlinjection.Rule(), &skippedRules)
	context.applyRisk(uncheckeddeployment.Rule(), &skippedRules)
	context.applyRisk(unencryptedasset.Rule(), &skippedRules)
	context.applyRisk(unencryptedcommunication.Rule(), &skippedRules)
	context.applyRisk(unguardedaccessfrominternet.Rule(), &skippedRules)
	context.applyRisk(unguardeddirectdatastoreaccess.Rule(), &skippedRules)
	context.applyRisk(unnecessarycommunicationlink.Rule(), &skippedRules)
	context.applyRisk(unnecessarydataasset.Rule(), &skippedRules)
	context.applyRisk(unnecessarydatatransfer.Rule(), &skippedRules)
	context.applyRisk(unnecessarytechnicalasset.Rule(), &skippedRules)
	context.applyRisk(untrusteddeserialization.Rule(), &skippedRules)
	context.applyRisk(wrongcommunicationlinkcontent.Rule(), &skippedRules)
	context.applyRisk(wrongtrustboundarycontent.Rule(), &skippedRules)
	context.applyRisk(xmlexternalentity.Rule(), &skippedRules)

	// NOW THE CUSTOM RISK RULES (if any)
	for id, customRule := range context.customRiskRules {
		_, ok := skippedRules[customRule.ID]
		if ok {
			if *context.verbose {
				fmt.Println("Skipping custom risk rule:", id)
			}
			delete(skippedRules, id)
		} else {
			if *context.verbose {
				fmt.Println("Executing custom risk rule:", id)
			}
			context.addToListOfSupportedTags(customRule.Tags)
			customRisks := customRule.GenerateRisks(&context.parsedModel)
			if len(customRisks) > 0 {
				context.parsedModel.GeneratedRisksByCategory[customRule.Category] = customRisks
			}

			if *context.verbose {
				fmt.Println("Added custom risks:", len(customRisks))
			}
		}
	}

	if len(skippedRules) > 0 {
		keys := make([]string, 0)
		for k := range skippedRules {
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			log.Println("Unknown risk rules to skip:", keys)
		}
	}

	// save also in map keyed by synthetic risk-id
	for _, category := range model.SortedRiskCategories(&context.parsedModel) {
		someRisks := model.SortedRisksOfCategory(&context.parsedModel, category)
		for _, risk := range someRisks {
			context.parsedModel.GeneratedRisksBySyntheticId[strings.ToLower(risk.SyntheticId)] = risk
		}
	}
}

// Unzip will decompress a zip archive, moving all files and folders
// within the zip file (parameter 1) to an output directory (parameter 2).
func (context *Context) unzip(src string, dest string) ([]string, error) {
	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		// Store filename/path for returning and using later on
		path := filepath.Join(dest, f.Name)
		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", path)
		}
		filenames = append(filenames, path)
		if f.FileInfo().IsDir() {
			// Make Folder
			_ = os.MkdirAll(path, os.ModePerm)
			continue
		}
		// Make File
		if err = os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
			return filenames, err
		}
		outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}
		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}
		_, err = io.Copy(outFile, rc)
		// Close the file without defer to close before next iteration of loop
		_ = outFile.Close()
		_ = rc.Close()
		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}

// ZipFiles compresses one or many files into a single zip archive file.
// Param 1: filename is the output zip file's name.
// Param 2: files is a list of files to add to the zip.
func (context *Context) zipFiles(filename string, files []string) error {
	newZipFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() { _ = newZipFile.Close() }()

	zipWriter := zip.NewWriter(newZipFile)
	defer func() { _ = zipWriter.Close() }()

	// Add files to zip
	for _, file := range files {
		if err = context.addFileToZip(zipWriter, file); err != nil {
			return err
		}
	}
	return nil
}

func (context *Context) addFileToZip(zipWriter *zip.Writer, filename string) error {
	fileToZip, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() { _ = fileToZip.Close() }()

	// Get the file information
	info, err := fileToZip.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}

	// Using FileInfoHeader() above only uses the basename of the file. If we want
	// to preserve the folder structure we can overwrite this with the full path.
	//header.Name = filename

	// Change to deflate to gain better compression
	// see http://golang.org/pkg/archive/zip/#pkg-constants
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, fileToZip)
	return err
}

func (context *Context) analyzeModelOnServerDirectly(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer func() {
		context.unlockFolder(folderNameOfKey)
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if *context.verbose {
				log.Println(err)
			}
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()

	dpi, err := strconv.Atoi(ginContext.DefaultQuery("dpi", strconv.Itoa(context.defaultGraphvizDPI)))
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return
	}

	_, yamlText, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return
	}
	tmpModelFile, err := os.CreateTemp(*context.tempFolder, "threagile-direct-analyze-*")
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.Remove(tmpModelFile.Name()) }()
	tmpOutputDir, err := os.MkdirTemp(*context.tempFolder, "threagile-direct-analyze-")
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()
	tmpResultFile, err := os.CreateTemp(*context.tempFolder, "threagile-result-*.zip")
	checkErr(err)
	defer func() { _ = os.Remove(tmpResultFile.Name()) }()

	err = os.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400)

	context.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, true, true, true, true, true, true, true, true, dpi)
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return
	}
	err = os.WriteFile(filepath.Join(tmpOutputDir, context.inputFile), []byte(yamlText), 0400)
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return
	}

	files := []string{
		filepath.Join(tmpOutputDir, context.inputFile),
		filepath.Join(tmpOutputDir, context.dataFlowDiagramFilenamePNG),
		filepath.Join(tmpOutputDir, context.dataAssetDiagramFilenamePNG),
		filepath.Join(tmpOutputDir, context.reportFilename),
		filepath.Join(tmpOutputDir, context.excelRisksFilename),
		filepath.Join(tmpOutputDir, context.excelTagsFilename),
		filepath.Join(tmpOutputDir, context.jsonRisksFilename),
		filepath.Join(tmpOutputDir, context.jsonTechnicalAssetsFilename),
		filepath.Join(tmpOutputDir, context.jsonStatsFilename),
	}
	if context.keepDiagramSourceFiles {
		files = append(files, filepath.Join(tmpOutputDir, context.dataFlowDiagramFilenameDOT))
		files = append(files, filepath.Join(tmpOutputDir, context.dataAssetDiagramFilenameDOT))
	}
	err = context.zipFiles(tmpResultFile.Name(), files)
	checkErr(err)
	if *context.verbose {
		fmt.Println("Streaming back result file: " + tmpResultFile.Name())
	}
	ginContext.FileAttachment(tmpResultFile.Name(), "threagile-result.zip")
}

func (context *Context) parseModel() {
	if *context.verbose {
		fmt.Println("Parsing model:", *context.modelFilename)
	}

	context.modelInput = *new(input.ModelInput).Defaults()
	loadError := context.modelInput.Load(*context.modelFilename)
	if loadError != nil {
		log.Fatal("Unable to parse model yaml: ", loadError)
	}

	//	data, _ := json.MarshalIndent(context.modelInput, "", "  ")
	//	fmt.Printf("%v\n", string(data))

	var businessCriticality types.Criticality
	switch context.modelInput.BusinessCriticality {
	case types.Archive.String():
		businessCriticality = types.Archive
	case types.Operational.String():
		businessCriticality = types.Operational
	case types.Important.String():
		businessCriticality = types.Important
	case types.Critical.String():
		businessCriticality = types.Critical
	case types.MissionCritical.String():
		businessCriticality = types.MissionCritical
	default:
		panic(errors.New("unknown 'business_criticality' value of application: " + context.modelInput.BusinessCriticality))
	}

	reportDate := time.Now()
	if len(context.modelInput.Date) > 0 {
		var parseError error
		reportDate, parseError = time.Parse("2006-01-02", context.modelInput.Date)
		if parseError != nil {
			panic(errors.New("unable to parse 'date' value of model file"))
		}
	}

	context.parsedModel = model.ParsedModel{
		Author:                         context.modelInput.Author,
		Title:                          context.modelInput.Title,
		Date:                           reportDate,
		ManagementSummaryComment:       context.modelInput.ManagementSummaryComment,
		BusinessCriticality:            businessCriticality,
		BusinessOverview:               removePathElementsFromImageFiles(context.modelInput.BusinessOverview),
		TechnicalOverview:              removePathElementsFromImageFiles(context.modelInput.TechnicalOverview),
		Questions:                      context.modelInput.Questions,
		AbuseCases:                     context.modelInput.AbuseCases,
		SecurityRequirements:           context.modelInput.SecurityRequirements,
		TagsAvailable:                  lowerCaseAndTrim(context.modelInput.TagsAvailable),
		DiagramTweakNodesep:            context.modelInput.DiagramTweakNodesep,
		DiagramTweakRanksep:            context.modelInput.DiagramTweakRanksep,
		DiagramTweakEdgeLayout:         context.modelInput.DiagramTweakEdgeLayout,
		DiagramTweakSuppressEdgeLabels: context.modelInput.DiagramTweakSuppressEdgeLabels,
		DiagramTweakLayoutLeftToRight:  context.modelInput.DiagramTweakLayoutLeftToRight,
		DiagramTweakInvisibleConnectionsBetweenAssets: context.modelInput.DiagramTweakInvisibleConnectionsBetweenAssets,
		DiagramTweakSameRankAssets:                    context.modelInput.DiagramTweakSameRankAssets,
	}

	context.parsedModel.CommunicationLinks = make(map[string]model.CommunicationLink)
	context.parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId = make(map[string][]model.CommunicationLink)
	context.parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId = make(map[string]model.TrustBoundary)
	context.parsedModel.GeneratedRisksByCategory = make(map[model.RiskCategory][]model.Risk)
	context.parsedModel.GeneratedRisksBySyntheticId = make(map[string]model.Risk)
	context.parsedModel.AllSupportedTags = make(map[string]bool)

	if context.parsedModel.DiagramTweakNodesep == 0 {
		context.parsedModel.DiagramTweakNodesep = 2
	}
	if context.parsedModel.DiagramTweakRanksep == 0 {
		context.parsedModel.DiagramTweakRanksep = 2
	}

	// Data Assets ===============================================================================
	context.parsedModel.DataAssets = make(map[string]model.DataAsset)
	for title, asset := range context.modelInput.DataAssets {
		id := fmt.Sprintf("%v", asset.ID)

		var usage types.Usage
		switch asset.Usage {
		case types.Business.String():
			usage = types.Business
		case types.DevOps.String():
			usage = types.DevOps
		default:
			panic(errors.New("unknown 'usage' value of data asset '" + title + "': " + asset.Usage))
		}

		var quantity types.Quantity
		switch asset.Quantity {
		case types.VeryFew.String():
			quantity = types.VeryFew
		case types.Few.String():
			quantity = types.Few
		case types.Many.String():
			quantity = types.Many
		case types.VeryMany.String():
			quantity = types.VeryMany
		default:
			panic(errors.New("unknown 'quantity' value of data asset '" + title + "': " + asset.Quantity))
		}

		var confidentiality types.Confidentiality
		switch asset.Confidentiality {
		case types.Public.String():
			confidentiality = types.Public
		case types.Internal.String():
			confidentiality = types.Internal
		case types.Restricted.String():
			confidentiality = types.Restricted
		case types.Confidential.String():
			confidentiality = types.Confidential
		case types.StrictlyConfidential.String():
			confidentiality = types.StrictlyConfidential
		default:
			panic(errors.New("unknown 'confidentiality' value of data asset '" + title + "': " + asset.Confidentiality))
		}

		var integrity types.Criticality
		switch asset.Integrity {
		case types.Archive.String():
			integrity = types.Archive
		case types.Operational.String():
			integrity = types.Operational
		case types.Important.String():
			integrity = types.Important
		case types.Critical.String():
			integrity = types.Critical
		case types.MissionCritical.String():
			integrity = types.MissionCritical
		default:
			panic(errors.New("unknown 'integrity' value of data asset '" + title + "': " + asset.Integrity))
		}

		var availability types.Criticality
		switch asset.Availability {
		case types.Archive.String():
			availability = types.Archive
		case types.Operational.String():
			availability = types.Operational
		case types.Important.String():
			availability = types.Important
		case types.Critical.String():
			availability = types.Critical
		case types.MissionCritical.String():
			availability = types.MissionCritical
		default:
			panic(errors.New("unknown 'availability' value of data asset '" + title + "': " + asset.Availability))
		}

		context.checkIdSyntax(id)
		if _, exists := context.parsedModel.DataAssets[id]; exists {
			panic(errors.New("duplicate id used: " + id))
		}
		context.parsedModel.DataAssets[id] = model.DataAsset{
			Id:                     id,
			Title:                  title,
			Usage:                  usage,
			Description:            withDefault(fmt.Sprintf("%v", asset.Description), title),
			Quantity:               quantity,
			Tags:                   context.checkTags(lowerCaseAndTrim(asset.Tags), "data asset '"+title+"'"),
			Origin:                 fmt.Sprintf("%v", asset.Origin),
			Owner:                  fmt.Sprintf("%v", asset.Owner),
			Confidentiality:        confidentiality,
			Integrity:              integrity,
			Availability:           availability,
			JustificationCiaRating: fmt.Sprintf("%v", asset.JustificationCiaRating),
		}
	}

	// Technical Assets ===============================================================================
	context.parsedModel.TechnicalAssets = make(map[string]model.TechnicalAsset)
	for title, asset := range context.modelInput.TechnicalAssets {
		id := fmt.Sprintf("%v", asset.ID)

		var usage types.Usage
		switch asset.Usage {
		case types.Business.String():
			usage = types.Business
		case types.DevOps.String():
			usage = types.DevOps
		default:
			panic(errors.New("unknown 'usage' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Usage)))
		}

		var dataAssetsProcessed = make([]string, 0)
		if asset.DataAssetsProcessed != nil {
			dataAssetsProcessed = make([]string, len(asset.DataAssetsProcessed))
			for i, parsedProcessedAsset := range asset.DataAssetsProcessed {
				referencedAsset := fmt.Sprintf("%v", parsedProcessedAsset)
				context.checkDataAssetTargetExists(referencedAsset, "technical asset '"+title+"'")
				dataAssetsProcessed[i] = referencedAsset
			}
		}

		var dataAssetsStored = make([]string, 0)
		if asset.DataAssetsStored != nil {
			dataAssetsStored = make([]string, len(asset.DataAssetsStored))
			for i, parsedStoredAssets := range asset.DataAssetsStored {
				referencedAsset := fmt.Sprintf("%v", parsedStoredAssets)
				context.checkDataAssetTargetExists(referencedAsset, "technical asset '"+title+"'")
				dataAssetsStored[i] = referencedAsset
			}
		}

		var technicalAssetType types.TechnicalAssetType
		switch asset.Type {
		case types.ExternalEntity.String():
			technicalAssetType = types.ExternalEntity
		case types.Process.String():
			technicalAssetType = types.Process
		case types.Datastore.String():
			technicalAssetType = types.Datastore
		default:
			panic(errors.New("unknown 'type' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Type)))
		}

		var technicalAssetSize types.TechnicalAssetSize
		switch asset.Size {
		case types.Service.String():
			technicalAssetSize = types.Service
		case types.System.String():
			technicalAssetSize = types.System
		case types.Application.String():
			technicalAssetSize = types.Application
		case types.Component.String():
			technicalAssetSize = types.Component
		default:
			panic(errors.New("unknown 'size' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Size)))
		}

		var technicalAssetTechnology types.TechnicalAssetTechnology
		switch asset.Technology {
		case types.UnknownTechnology.String():
			technicalAssetTechnology = types.UnknownTechnology
		case types.ClientSystem.String():
			technicalAssetTechnology = types.ClientSystem
		case types.Browser.String():
			technicalAssetTechnology = types.Browser
		case types.Desktop.String():
			technicalAssetTechnology = types.Desktop
		case types.MobileApp.String():
			technicalAssetTechnology = types.MobileApp
		case types.DevOpsClient.String():
			technicalAssetTechnology = types.DevOpsClient
		case types.WebServer.String():
			technicalAssetTechnology = types.WebServer
		case types.WebApplication.String():
			technicalAssetTechnology = types.WebApplication
		case types.ApplicationServer.String():
			technicalAssetTechnology = types.ApplicationServer
		case types.Database.String():
			technicalAssetTechnology = types.Database
		case types.FileServer.String():
			technicalAssetTechnology = types.FileServer
		case types.LocalFileSystem.String():
			technicalAssetTechnology = types.LocalFileSystem
		case types.ERP.String():
			technicalAssetTechnology = types.ERP
		case types.CMS.String():
			technicalAssetTechnology = types.CMS
		case types.WebServiceREST.String():
			technicalAssetTechnology = types.WebServiceREST
		case types.WebServiceSOAP.String():
			technicalAssetTechnology = types.WebServiceSOAP
		case types.EJB.String():
			technicalAssetTechnology = types.EJB
		case types.SearchIndex.String():
			technicalAssetTechnology = types.SearchIndex
		case types.SearchEngine.String():
			technicalAssetTechnology = types.SearchEngine
		case types.ServiceRegistry.String():
			technicalAssetTechnology = types.ServiceRegistry
		case types.ReverseProxy.String():
			technicalAssetTechnology = types.ReverseProxy
		case types.LoadBalancer.String():
			technicalAssetTechnology = types.LoadBalancer
		case types.BuildPipeline.String():
			technicalAssetTechnology = types.BuildPipeline
		case types.SourcecodeRepository.String():
			technicalAssetTechnology = types.SourcecodeRepository
		case types.ArtifactRegistry.String():
			technicalAssetTechnology = types.ArtifactRegistry
		case types.CodeInspectionPlatform.String():
			technicalAssetTechnology = types.CodeInspectionPlatform
		case types.Monitoring.String():
			technicalAssetTechnology = types.Monitoring
		case types.LDAPServer.String():
			technicalAssetTechnology = types.LDAPServer
		case types.ContainerPlatform.String():
			technicalAssetTechnology = types.ContainerPlatform
		case types.BatchProcessing.String():
			technicalAssetTechnology = types.BatchProcessing
		case types.EventListener.String():
			technicalAssetTechnology = types.EventListener
		case types.IdentityProvider.String():
			technicalAssetTechnology = types.IdentityProvider
		case types.IdentityStoreLDAP.String():
			technicalAssetTechnology = types.IdentityStoreLDAP
		case types.IdentityStoreDatabase.String():
			technicalAssetTechnology = types.IdentityStoreDatabase
		case types.Tool.String():
			technicalAssetTechnology = types.Tool
		case types.CLI.String():
			technicalAssetTechnology = types.CLI
		case types.Task.String():
			technicalAssetTechnology = types.Task
		case types.Function.String():
			technicalAssetTechnology = types.Function
		case types.Gateway.String():
			technicalAssetTechnology = types.Gateway
		case types.IoTDevice.String():
			technicalAssetTechnology = types.IoTDevice
		case types.MessageQueue.String():
			technicalAssetTechnology = types.MessageQueue
		case types.StreamProcessing.String():
			technicalAssetTechnology = types.StreamProcessing
		case types.ServiceMesh.String():
			technicalAssetTechnology = types.ServiceMesh
		case types.DataLake.String():
			technicalAssetTechnology = types.DataLake
		case types.BigDataPlatform.String():
			technicalAssetTechnology = types.BigDataPlatform
		case types.ReportEngine.String():
			technicalAssetTechnology = types.ReportEngine
		case types.AI.String():
			technicalAssetTechnology = types.AI
		case types.MailServer.String():
			technicalAssetTechnology = types.MailServer
		case types.Vault.String():
			technicalAssetTechnology = types.Vault
		case types.HSM.String():
			technicalAssetTechnology = types.HSM
		case types.WAF.String():
			technicalAssetTechnology = types.WAF
		case types.IDS.String():
			technicalAssetTechnology = types.IDS
		case types.IPS.String():
			technicalAssetTechnology = types.IPS
		case types.Scheduler.String():
			technicalAssetTechnology = types.Scheduler
		case types.Mainframe.String():
			technicalAssetTechnology = types.Mainframe
		case types.BlockStorage.String():
			technicalAssetTechnology = types.BlockStorage
		case types.Library.String():
			technicalAssetTechnology = types.Library
		default:
			panic(errors.New("unknown 'technology' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Technology)))
		}

		var encryption types.EncryptionStyle
		switch asset.Encryption {
		case types.NoneEncryption.String():
			encryption = types.NoneEncryption
		case types.Transparent.String():
			encryption = types.Transparent
		case types.DataWithSymmetricSharedKey.String():
			encryption = types.DataWithSymmetricSharedKey
		case types.DataWithAsymmetricSharedKey.String():
			encryption = types.DataWithAsymmetricSharedKey
		case types.DataWithEndUserIndividualKey.String():
			encryption = types.DataWithEndUserIndividualKey
		default:
			panic(errors.New("unknown 'encryption' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Encryption)))
		}

		var technicalAssetMachine types.TechnicalAssetMachine
		switch asset.Machine {
		case types.Physical.String():
			technicalAssetMachine = types.Physical
		case types.Virtual.String():
			technicalAssetMachine = types.Virtual
		case types.Container.String():
			technicalAssetMachine = types.Container
		case types.Serverless.String():
			technicalAssetMachine = types.Serverless
		default:
			panic(errors.New("unknown 'machine' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Machine)))
		}

		var confidentiality types.Confidentiality
		switch asset.Confidentiality {
		case types.Public.String():
			confidentiality = types.Public
		case types.Internal.String():
			confidentiality = types.Internal
		case types.Restricted.String():
			confidentiality = types.Restricted
		case types.Confidential.String():
			confidentiality = types.Confidential
		case types.StrictlyConfidential.String():
			confidentiality = types.StrictlyConfidential
		default:
			panic(errors.New("unknown 'confidentiality' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Confidentiality)))
		}

		var integrity types.Criticality
		switch asset.Integrity {
		case types.Archive.String():
			integrity = types.Archive
		case types.Operational.String():
			integrity = types.Operational
		case types.Important.String():
			integrity = types.Important
		case types.Critical.String():
			integrity = types.Critical
		case types.MissionCritical.String():
			integrity = types.MissionCritical
		default:
			panic(errors.New("unknown 'integrity' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Integrity)))
		}

		var availability types.Criticality
		switch asset.Availability {
		case types.Archive.String():
			availability = types.Archive
		case types.Operational.String():
			availability = types.Operational
		case types.Important.String():
			availability = types.Important
		case types.Critical.String():
			availability = types.Critical
		case types.MissionCritical.String():
			availability = types.MissionCritical
		default:
			panic(errors.New("unknown 'availability' value of technical asset '" + title + "': " + fmt.Sprintf("%v", asset.Availability)))
		}

		dataFormatsAccepted := make([]types.DataFormat, 0)
		if asset.DataFormatsAccepted != nil {
			for _, dataFormatName := range asset.DataFormatsAccepted {
				switch dataFormatName {
				case types.JSON.String():
					dataFormatsAccepted = append(dataFormatsAccepted, types.JSON)
				case types.XML.String():
					dataFormatsAccepted = append(dataFormatsAccepted, types.XML)
				case types.Serialization.String():
					dataFormatsAccepted = append(dataFormatsAccepted, types.Serialization)
				case types.File.String():
					dataFormatsAccepted = append(dataFormatsAccepted, types.File)
				case types.CSV.String():
					dataFormatsAccepted = append(dataFormatsAccepted, types.CSV)
				default:
					panic(errors.New("unknown 'data_formats_accepted' value of technical asset '" + title + "': " + fmt.Sprintf("%v", dataFormatName)))
				}
			}
		}

		communicationLinks := make([]model.CommunicationLink, 0)
		if asset.CommunicationLinks != nil {
			for commLinkTitle, commLink := range asset.CommunicationLinks {
				constraint := true
				weight := 1
				var protocol types.Protocol
				var authentication types.Authentication
				var authorization types.Authorization
				var usage types.Usage
				var dataAssetsSent []string
				var dataAssetsReceived []string

				switch commLink.Authentication {
				case types.NoneAuthentication.String():
					authentication = types.NoneAuthentication
				case types.Credentials.String():
					authentication = types.Credentials
				case types.SessionId.String():
					authentication = types.SessionId
				case types.Token.String():
					authentication = types.Token
				case types.ClientCertificate.String():
					authentication = types.ClientCertificate
				case types.TwoFactor.String():
					authentication = types.TwoFactor
				case types.Externalized.String():
					authentication = types.Externalized
				default:
					panic(errors.New("unknown 'authentication' value of technical asset '" + title + "' communication link '" + commLinkTitle + "': " + fmt.Sprintf("%v", commLink.Authentication)))
				}

				switch commLink.Authorization {
				case types.NoneAuthorization.String():
					authorization = types.NoneAuthorization
				case types.TechnicalUser.String():
					authorization = types.TechnicalUser
				case types.EndUserIdentityPropagation.String():
					authorization = types.EndUserIdentityPropagation
				default:
					panic(errors.New("unknown 'authorization' value of technical asset '" + title + "' communication link '" + commLinkTitle + "': " + fmt.Sprintf("%v", commLink.Authorization)))
				}

				switch commLink.Usage {
				case types.Business.String():
					usage = types.Business
				case types.DevOps.String():
					usage = types.DevOps
				default:
					panic(errors.New("unknown 'usage' value of technical asset '" + title + "' communication link '" + commLinkTitle + "': " + fmt.Sprintf("%v", commLink.Usage)))
				}

				switch commLink.Protocol {
				case types.UnknownProtocol.String():
					protocol = types.UnknownProtocol
				case types.HTTP.String():
					protocol = types.HTTP
				case types.HTTPS.String():
					protocol = types.HTTPS
				case types.WS.String():
					protocol = types.WS
				case types.WSS.String():
					protocol = types.WSS
				case types.MQTT.String():
					protocol = types.MQTT
				case types.JDBC.String():
					protocol = types.JDBC
				case types.JdbcEncrypted.String():
					protocol = types.JdbcEncrypted
				case types.ODBC.String():
					protocol = types.ODBC
				case types.OdbcEncrypted.String():
					protocol = types.OdbcEncrypted
				case types.SqlAccessProtocol.String():
					protocol = types.SqlAccessProtocol
				case types.SqlAccessProtocolEncrypted.String():
					protocol = types.SqlAccessProtocolEncrypted
				case types.NosqlAccessProtocol.String():
					protocol = types.NosqlAccessProtocol
				case types.NosqlAccessProtocolEncrypted.String():
					protocol = types.NosqlAccessProtocolEncrypted
				case types.TEXT.String():
					protocol = types.TEXT
				case types.TextEncrypted.String():
					protocol = types.TextEncrypted
				case types.BINARY.String():
					protocol = types.BINARY
				case types.BinaryEncrypted.String():
					protocol = types.BinaryEncrypted
				case types.SSH.String():
					protocol = types.SSH
				case types.SshTunnel.String():
					protocol = types.SshTunnel
				case types.SMTP.String():
					protocol = types.SMTP
				case types.SmtpEncrypted.String():
					protocol = types.SmtpEncrypted
				case types.POP3.String():
					protocol = types.POP3
				case types.Pop3Encrypted.String():
					protocol = types.Pop3Encrypted
				case types.IMAP.String():
					protocol = types.IMAP
				case types.ImapEncrypted.String():
					protocol = types.ImapEncrypted
				case types.FTP.String():
					protocol = types.FTP
				case types.FTPS.String():
					protocol = types.FTPS
				case types.SFTP.String():
					protocol = types.SFTP
				case types.SCP.String():
					protocol = types.SCP
				case types.LDAP.String():
					protocol = types.LDAP
				case types.LDAPS.String():
					protocol = types.LDAPS
				case types.JMS.String():
					protocol = types.JMS
				case types.NFS.String():
					protocol = types.NFS
				case types.SMB.String():
					protocol = types.SMB
				case types.SmbEncrypted.String():
					protocol = types.SmbEncrypted
				case types.LocalFileAccess.String():
					protocol = types.LocalFileAccess
				case types.NRPE.String():
					protocol = types.NRPE
				case types.XMPP.String():
					protocol = types.XMPP
				case types.IIOP.String():
					protocol = types.IIOP
				case types.IiopEncrypted.String():
					protocol = types.IiopEncrypted
				case types.JRMP.String():
					protocol = types.JRMP
				case types.JrmpEncrypted.String():
					protocol = types.JrmpEncrypted
				case types.InProcessLibraryCall.String():
					protocol = types.InProcessLibraryCall
				case types.ContainerSpawning.String():
					protocol = types.ContainerSpawning
				default:
					panic(errors.New("unknown 'protocol' of technical asset '" + title + "' communication link '" + commLinkTitle + "': " + fmt.Sprintf("%v", commLink.Protocol)))
				}

				if commLink.DataAssetsSent != nil {
					for _, dataAssetSent := range commLink.DataAssetsSent {
						referencedAsset := fmt.Sprintf("%v", dataAssetSent)
						context.checkDataAssetTargetExists(referencedAsset, "communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
						dataAssetsSent = append(dataAssetsSent, referencedAsset)
					}
				}

				if commLink.DataAssetsReceived != nil {
					for _, dataAssetReceived := range commLink.DataAssetsReceived {
						referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
						context.checkDataAssetTargetExists(referencedAsset, "communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
						dataAssetsReceived = append(dataAssetsReceived, referencedAsset)
					}
				}

				if commLink.DiagramTweakWeight > 0 {
					weight = commLink.DiagramTweakWeight
				}

				constraint = !commLink.DiagramTweakConstraint

				dataFlowTitle := fmt.Sprintf("%v", commLinkTitle)
				commLink := model.CommunicationLink{
					Id:                     createDataFlowId(id, dataFlowTitle),
					SourceId:               id,
					TargetId:               commLink.Target,
					Title:                  dataFlowTitle,
					Description:            withDefault(commLink.Description, dataFlowTitle),
					Protocol:               protocol,
					Authentication:         authentication,
					Authorization:          authorization,
					Usage:                  usage,
					Tags:                   context.checkTags(lowerCaseAndTrim(commLink.Tags), "communication link '"+commLinkTitle+"' of technical asset '"+title+"'"),
					VPN:                    commLink.VPN,
					IpFiltered:             commLink.IpFiltered,
					Readonly:               commLink.Readonly,
					DataAssetsSent:         dataAssetsSent,
					DataAssetsReceived:     dataAssetsReceived,
					DiagramTweakWeight:     weight,
					DiagramTweakConstraint: constraint,
				}
				communicationLinks = append(communicationLinks, commLink)
				// track all comm links
				context.parsedModel.CommunicationLinks[commLink.Id] = commLink
				// keep track of map of *all* comm links mapped by target-id (to be able to look up "who is calling me" kind of things)
				context.parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[commLink.TargetId] = append(
					context.parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[commLink.TargetId], commLink)
			}
		}

		context.checkIdSyntax(id)
		if _, exists := context.parsedModel.TechnicalAssets[id]; exists {
			panic(errors.New("duplicate id used: " + id))
		}
		context.parsedModel.TechnicalAssets[id] = model.TechnicalAsset{
			Id:                      id,
			Usage:                   usage,
			Title:                   title, //fmt.Sprintf("%v", asset["title"]),
			Description:             withDefault(fmt.Sprintf("%v", asset.Description), title),
			Type:                    technicalAssetType,
			Size:                    technicalAssetSize,
			Technology:              technicalAssetTechnology,
			Tags:                    context.checkTags(lowerCaseAndTrim(asset.Tags), "technical asset '"+title+"'"),
			Machine:                 technicalAssetMachine,
			Internet:                asset.Internet,
			Encryption:              encryption,
			MultiTenant:             asset.MultiTenant,
			Redundant:               asset.Redundant,
			CustomDevelopedParts:    asset.CustomDevelopedParts,
			UsedAsClientByHuman:     asset.UsedAsClientByHuman,
			OutOfScope:              asset.OutOfScope,
			JustificationOutOfScope: fmt.Sprintf("%v", asset.JustificationOutOfScope),
			Owner:                   fmt.Sprintf("%v", asset.Owner),
			Confidentiality:         confidentiality,
			Integrity:               integrity,
			Availability:            availability,
			JustificationCiaRating:  fmt.Sprintf("%v", asset.JustificationCiaRating),
			DataAssetsProcessed:     dataAssetsProcessed,
			DataAssetsStored:        dataAssetsStored,
			DataFormatsAccepted:     dataFormatsAccepted,
			CommunicationLinks:      communicationLinks,
			DiagramTweakOrder:       asset.DiagramTweakOrder,
		}
	}

	// Trust Boundaries ===============================================================================
	checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries := make(map[string]bool)
	context.parsedModel.TrustBoundaries = make(map[string]model.TrustBoundary)
	for title, boundary := range context.modelInput.TrustBoundaries {
		id := fmt.Sprintf("%v", boundary.ID)

		var technicalAssetsInside = make([]string, 0)
		if boundary.TechnicalAssetsInside != nil {
			parsedInsideAssets := boundary.TechnicalAssetsInside
			technicalAssetsInside = make([]string, len(parsedInsideAssets))
			for i, parsedInsideAsset := range parsedInsideAssets {
				technicalAssetsInside[i] = fmt.Sprintf("%v", parsedInsideAsset)
				_, found := context.parsedModel.TechnicalAssets[technicalAssetsInside[i]]
				if !found {
					panic(errors.New("missing referenced technical asset " + technicalAssetsInside[i] + " at trust boundary '" + title + "'"))
				}
				if checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries[technicalAssetsInside[i]] == true {
					panic(errors.New("referenced technical asset " + technicalAssetsInside[i] + " at trust boundary '" + title + "' is modeled in multiple trust boundaries"))
				}
				checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries[technicalAssetsInside[i]] = true
				//fmt.Println("asset "+technicalAssetsInside[i]+" at i="+strconv.Itoa(i))
			}
		}

		var trustBoundariesNested = make([]string, 0)
		if boundary.TrustBoundariesNested != nil {
			parsedNestedBoundaries := boundary.TrustBoundariesNested
			trustBoundariesNested = make([]string, len(parsedNestedBoundaries))
			for i, parsedNestedBoundary := range parsedNestedBoundaries {
				trustBoundariesNested[i] = fmt.Sprintf("%v", parsedNestedBoundary)
			}
		}

		var trustBoundaryType types.TrustBoundaryType
		switch boundary.Type {
		case types.NetworkOnPrem.String():
			trustBoundaryType = types.NetworkOnPrem
		case types.NetworkDedicatedHoster.String():
			trustBoundaryType = types.NetworkDedicatedHoster
		case types.NetworkVirtualLAN.String():
			trustBoundaryType = types.NetworkVirtualLAN
		case types.NetworkCloudProvider.String():
			trustBoundaryType = types.NetworkCloudProvider
		case types.NetworkCloudSecurityGroup.String():
			trustBoundaryType = types.NetworkCloudSecurityGroup
		case types.NetworkPolicyNamespaceIsolation.String():
			trustBoundaryType = types.NetworkPolicyNamespaceIsolation
		case types.ExecutionEnvironment.String():
			trustBoundaryType = types.ExecutionEnvironment
		default:
			panic(errors.New("unknown 'type' of trust boundary '" + title + "': " + fmt.Sprintf("%v", boundary.Type)))
		}

		trustBoundary := model.TrustBoundary{
			Id:                    id,
			Title:                 title, //fmt.Sprintf("%v", boundary["title"]),
			Description:           withDefault(fmt.Sprintf("%v", boundary.Description), title),
			Type:                  trustBoundaryType,
			Tags:                  context.checkTags(lowerCaseAndTrim(boundary.Tags), "trust boundary '"+title+"'"),
			TechnicalAssetsInside: technicalAssetsInside,
			TrustBoundariesNested: trustBoundariesNested,
		}
		context.checkIdSyntax(id)
		if _, exists := context.parsedModel.TrustBoundaries[id]; exists {
			panic(errors.New("duplicate id used: " + id))
		}
		context.parsedModel.TrustBoundaries[id] = trustBoundary
		for _, technicalAsset := range trustBoundary.TechnicalAssetsInside {
			context.parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[technicalAsset] = trustBoundary
			//fmt.Println("Asset "+technicalAsset+" is directly in trust boundary "+trustBoundary.Id)
		}
	}
	context.checkNestedTrustBoundariesExisting()

	// Shared Runtime ===============================================================================
	context.parsedModel.SharedRuntimes = make(map[string]model.SharedRuntime)
	for title, runtime := range context.modelInput.SharedRuntimes {
		id := fmt.Sprintf("%v", runtime.ID)

		var technicalAssetsRunning = make([]string, 0)
		if runtime.TechnicalAssetsRunning != nil {
			parsedRunningAssets := runtime.TechnicalAssetsRunning
			technicalAssetsRunning = make([]string, len(parsedRunningAssets))
			for i, parsedRunningAsset := range parsedRunningAssets {
				assetId := fmt.Sprintf("%v", parsedRunningAsset)
				context.checkTechnicalAssetExists(assetId, "shared runtime '"+title+"'", false)
				technicalAssetsRunning[i] = assetId
			}
		}

		sharedRuntime := model.SharedRuntime{
			Id:                     id,
			Title:                  title, //fmt.Sprintf("%v", boundary["title"]),
			Description:            withDefault(fmt.Sprintf("%v", runtime.Description), title),
			Tags:                   context.checkTags(runtime.Tags, "shared runtime '"+title+"'"),
			TechnicalAssetsRunning: technicalAssetsRunning,
		}
		context.checkIdSyntax(id)
		if _, exists := context.parsedModel.SharedRuntimes[id]; exists {
			panic(errors.New("duplicate id used: " + id))
		}
		context.parsedModel.SharedRuntimes[id] = sharedRuntime
	}

	// Individual Risk Categories (just used as regular risk categories) ===============================================================================
	context.parsedModel.IndividualRiskCategories = make(map[string]model.RiskCategory)
	for title, individualCategory := range context.modelInput.IndividualRiskCategories {
		id := fmt.Sprintf("%v", individualCategory.ID)

		var function types.RiskFunction
		switch individualCategory.Function {
		case types.BusinessSide.String():
			function = types.BusinessSide
		case types.Architecture.String():
			function = types.Architecture
		case types.Development.String():
			function = types.Development
		case types.Operations.String():
			function = types.Operations
		default:
			panic(errors.New("unknown 'function' value of individual risk category '" + title + "': " + fmt.Sprintf("%v", individualCategory.Function)))
		}

		var stride types.STRIDE
		switch individualCategory.STRIDE {
		case types.Spoofing.String():
			stride = types.Spoofing
		case types.Tampering.String():
			stride = types.Tampering
		case types.Repudiation.String():
			stride = types.Repudiation
		case types.InformationDisclosure.String():
			stride = types.InformationDisclosure
		case types.DenialOfService.String():
			stride = types.DenialOfService
		case types.ElevationOfPrivilege.String():
			stride = types.ElevationOfPrivilege
		default:
			panic(errors.New("unknown 'stride' value of individual risk category '" + title + "': " + fmt.Sprintf("%v", individualCategory.STRIDE)))
		}

		cat := model.RiskCategory{
			Id:                         id,
			Title:                      title,
			Description:                withDefault(fmt.Sprintf("%v", individualCategory.Description), title),
			Impact:                     fmt.Sprintf("%v", individualCategory.Impact),
			ASVS:                       fmt.Sprintf("%v", individualCategory.ASVS),
			CheatSheet:                 fmt.Sprintf("%v", individualCategory.CheatSheet),
			Action:                     fmt.Sprintf("%v", individualCategory.Action),
			Mitigation:                 fmt.Sprintf("%v", individualCategory.Mitigation),
			Check:                      fmt.Sprintf("%v", individualCategory.Check),
			DetectionLogic:             fmt.Sprintf("%v", individualCategory.DetectionLogic),
			RiskAssessment:             fmt.Sprintf("%v", individualCategory.RiskAssessment),
			FalsePositives:             fmt.Sprintf("%v", individualCategory.FalsePositives),
			Function:                   function,
			STRIDE:                     stride,
			ModelFailurePossibleReason: individualCategory.ModelFailurePossibleReason,
			CWE:                        individualCategory.CWE,
		}
		context.checkIdSyntax(id)
		if _, exists := context.parsedModel.IndividualRiskCategories[id]; exists {
			panic(errors.New("duplicate id used: " + id))
		}
		context.parsedModel.IndividualRiskCategories[id] = cat

		// NOW THE INDIVIDUAL RISK INSTANCES:
		//individualRiskInstances := make([]model.Risk, 0)
		if individualCategory.RisksIdentified != nil { // TODO: also add syntax checks of input YAML when linked asset is not found or when synthetic-id is already used...
			for title, individualRiskInstance := range individualCategory.RisksIdentified {
				var severity types.RiskSeverity
				var exploitationLikelihood types.RiskExploitationLikelihood
				var exploitationImpact types.RiskExploitationImpact
				var mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId string
				var dataBreachProbability types.DataBreachProbability
				var dataBreachTechnicalAssetIDs []string

				switch individualRiskInstance.Severity {
				case types.LowSeverity.String():
					severity = types.LowSeverity
				case types.MediumSeverity.String():
					severity = types.MediumSeverity
				case types.ElevatedSeverity.String():
					severity = types.ElevatedSeverity
				case types.HighSeverity.String():
					severity = types.HighSeverity
				case types.CriticalSeverity.String():
					severity = types.CriticalSeverity
				case "": // added default
					severity = types.MediumSeverity
				default:
					panic(errors.New("unknown 'severity' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", individualRiskInstance.Severity)))
				}

				switch individualRiskInstance.ExploitationLikelihood {
				case types.Unlikely.String():
					exploitationLikelihood = types.Unlikely
				case types.Likely.String():
					exploitationLikelihood = types.Likely
				case types.VeryLikely.String():
					exploitationLikelihood = types.VeryLikely
				case types.Frequent.String():
					exploitationLikelihood = types.Frequent
				case "": // added default
					exploitationLikelihood = types.Likely
				default:
					panic(errors.New("unknown 'exploitation_likelihood' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", individualRiskInstance.ExploitationLikelihood)))
				}

				switch individualRiskInstance.ExploitationImpact {
				case types.LowImpact.String():
					exploitationImpact = types.LowImpact
				case types.MediumImpact.String():
					exploitationImpact = types.MediumImpact
				case types.HighImpact.String():
					exploitationImpact = types.HighImpact
				case types.VeryHighImpact.String():
					exploitationImpact = types.VeryHighImpact
				case "": // added default
					exploitationImpact = types.MediumImpact
				default:
					panic(errors.New("unknown 'exploitation_impact' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", individualRiskInstance.ExploitationImpact)))
				}

				if len(individualRiskInstance.MostRelevantDataAsset) > 0 {
					mostRelevantDataAssetId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantDataAsset)
					context.checkDataAssetTargetExists(mostRelevantDataAssetId, "individual risk '"+title+"'")
				}

				if len(individualRiskInstance.MostRelevantTechnicalAsset) > 0 {
					mostRelevantTechnicalAssetId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantTechnicalAsset)
					context.checkTechnicalAssetExists(mostRelevantTechnicalAssetId, "individual risk '"+title+"'", false)
				}

				if len(individualRiskInstance.MostRelevantCommunicationLink) > 0 {
					mostRelevantCommunicationLinkId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantCommunicationLink)
					context.checkCommunicationLinkExists(mostRelevantCommunicationLinkId, "individual risk '"+title+"'")
				}

				if len(individualRiskInstance.MostRelevantTrustBoundary) > 0 {
					mostRelevantTrustBoundaryId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantTrustBoundary)
					context.checkTrustBoundaryExists(mostRelevantTrustBoundaryId, "individual risk '"+title+"'")
				}

				if len(individualRiskInstance.MostRelevantSharedRuntime) > 0 {
					mostRelevantSharedRuntimeId = fmt.Sprintf("%v", individualRiskInstance.MostRelevantSharedRuntime)
					context.checkSharedRuntimeExists(mostRelevantSharedRuntimeId, "individual risk '"+title+"'")
				}

				switch individualRiskInstance.DataBreachProbability {
				case types.Improbable.String():
					dataBreachProbability = types.Improbable
				case types.Possible.String():
					dataBreachProbability = types.Possible
				case types.Probable.String():
					dataBreachProbability = types.Probable
				case "": // added default
					dataBreachProbability = types.Possible
				default:
					panic(errors.New("unknown 'data_breach_probability' value of individual risk instance '" + title + "': " + fmt.Sprintf("%v", individualRiskInstance.DataBreachProbability)))
				}

				if individualRiskInstance.DataBreachTechnicalAssets != nil {
					dataBreachTechnicalAssetIDs = make([]string, len(individualRiskInstance.DataBreachTechnicalAssets))
					for i, parsedReferencedAsset := range individualRiskInstance.DataBreachTechnicalAssets {
						assetId := fmt.Sprintf("%v", parsedReferencedAsset)
						context.checkTechnicalAssetExists(assetId, "data breach technical assets of individual risk '"+title+"'", false)
						dataBreachTechnicalAssetIDs[i] = assetId
					}
				}

				individualRiskInstance := model.Risk{
					SyntheticId:                     createSyntheticId(cat.Id, mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId),
					Title:                           fmt.Sprintf("%v", title),
					Category:                        cat,
					Severity:                        severity,
					ExploitationLikelihood:          exploitationLikelihood,
					ExploitationImpact:              exploitationImpact,
					MostRelevantDataAssetId:         mostRelevantDataAssetId,
					MostRelevantTechnicalAssetId:    mostRelevantTechnicalAssetId,
					MostRelevantCommunicationLinkId: mostRelevantCommunicationLinkId,
					MostRelevantTrustBoundaryId:     mostRelevantTrustBoundaryId,
					MostRelevantSharedRuntimeId:     mostRelevantSharedRuntimeId,
					DataBreachProbability:           dataBreachProbability,
					DataBreachTechnicalAssetIDs:     dataBreachTechnicalAssetIDs,
				}
				context.parsedModel.GeneratedRisksByCategory[cat] = append(context.parsedModel.GeneratedRisksByCategory[cat], individualRiskInstance)
			}
		}
	}

	// Risk Tracking ===============================================================================
	context.parsedModel.RiskTracking = make(map[string]model.RiskTracking)
	for syntheticRiskId, riskTracking := range context.modelInput.RiskTracking {
		justification := fmt.Sprintf("%v", riskTracking.Justification)
		checkedBy := fmt.Sprintf("%v", riskTracking.CheckedBy)
		ticket := fmt.Sprintf("%v", riskTracking.Ticket)
		var date time.Time
		if len(riskTracking.Date) > 0 {
			var parseError error
			date, parseError = time.Parse("2006-01-02", riskTracking.Date)
			if parseError != nil {
				panic(errors.New("unable to parse 'date' of risk tracking '" + syntheticRiskId + "': " + riskTracking.Date))
			}
		}

		var status types.RiskStatus
		switch riskTracking.Status {
		case types.Unchecked.String():
			status = types.Unchecked
		case types.Mitigated.String():
			status = types.Mitigated
		case types.InProgress.String():
			status = types.InProgress
		case types.Accepted.String():
			status = types.Accepted
		case types.InDiscussion.String():
			status = types.InDiscussion
		case types.FalsePositive.String():
			status = types.FalsePositive
		default:
			panic(errors.New("unknown 'status' value of risk tracking '" + syntheticRiskId + "': " + riskTracking.Status))
		}

		tracking := model.RiskTracking{
			SyntheticRiskId: strings.TrimSpace(syntheticRiskId),
			Justification:   justification,
			CheckedBy:       checkedBy,
			Ticket:          ticket,
			Date:            date,
			Status:          status,
		}
		if strings.Contains(syntheticRiskId, "*") { // contains a wildcard char
			context.deferredRiskTrackingDueToWildcardMatching[syntheticRiskId] = tracking
		} else {
			context.parsedModel.RiskTracking[syntheticRiskId] = tracking
		}
	}

	// ====================== model consistency check (linking)
	for _, technicalAsset := range context.parsedModel.TechnicalAssets {
		for _, commLink := range technicalAsset.CommunicationLinks {
			context.checkTechnicalAssetExists(commLink.TargetId, "communication link '"+commLink.Title+"' of technical asset '"+technicalAsset.Title+"'", false)
		}
	}
}

func createSyntheticId(categoryId string,
	mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId string) string {
	result := categoryId
	if len(mostRelevantTechnicalAssetId) > 0 {
		result += "@" + mostRelevantTechnicalAssetId
	}
	if len(mostRelevantCommunicationLinkId) > 0 {
		result += "@" + mostRelevantCommunicationLinkId
	}
	if len(mostRelevantTrustBoundaryId) > 0 {
		result += "@" + mostRelevantTrustBoundaryId
	}
	if len(mostRelevantSharedRuntimeId) > 0 {
		result += "@" + mostRelevantSharedRuntimeId
	}
	if len(mostRelevantDataAssetId) > 0 {
		result += "@" + mostRelevantDataAssetId
	}
	return result
}

func createDataFlowId(sourceAssetId, title string) string {
	reg, err := regexp.Compile("[^A-Za-z0-9]+")
	checkErr(err)
	return sourceAssetId + ">" + strings.Trim(reg.ReplaceAllString(strings.ToLower(title), "-"), "- ")
}

func (context *Context) checkDataAssetTargetExists(referencedAsset, where string) {
	if _, ok := context.parsedModel.DataAssets[referencedAsset]; !ok {
		panic(errors.New("missing referenced data asset target at " + where + ": " + referencedAsset))
	}
}

func (context *Context) checkTrustBoundaryExists(referencedId, where string) {
	if _, ok := context.parsedModel.TrustBoundaries[referencedId]; !ok {
		panic(errors.New("missing referenced trust boundary at " + where + ": " + referencedId))
	}
}

func (context *Context) checkSharedRuntimeExists(referencedId, where string) {
	if _, ok := context.parsedModel.SharedRuntimes[referencedId]; !ok {
		panic(errors.New("missing referenced shared runtime at " + where + ": " + referencedId))
	}
}

func (context *Context) checkCommunicationLinkExists(referencedId, where string) {
	if _, ok := context.parsedModel.CommunicationLinks[referencedId]; !ok {
		panic(errors.New("missing referenced communication link at " + where + ": " + referencedId))
	}
}

func (context *Context) checkTechnicalAssetExists(referencedAsset, where string, onlyForTweak bool) {
	if _, ok := context.parsedModel.TechnicalAssets[referencedAsset]; !ok {
		suffix := ""
		if onlyForTweak {
			suffix = " (only referenced in diagram tweak)"
		}
		panic(errors.New("missing referenced technical asset target" + suffix + " at " + where + ": " + referencedAsset))
	}
}

func (context *Context) checkNestedTrustBoundariesExisting() {
	for _, trustBoundary := range context.parsedModel.TrustBoundaries {
		for _, nestedId := range trustBoundary.TrustBoundariesNested {
			if _, ok := context.parsedModel.TrustBoundaries[nestedId]; !ok {
				panic(errors.New("missing referenced nested trust boundary: " + nestedId))
			}
		}
	}
}

// in order to prevent Path-Traversal like stuff...
func removePathElementsFromImageFiles(overview input.Overview) input.Overview {
	for i := range overview.Images {
		newValue := make(map[string]string)
		for file, desc := range overview.Images[i] {
			newValue[filepath.Base(file)] = desc
		}
		overview.Images[i] = newValue
	}
	return overview
}

func (context *Context) writeDataFlowDiagramGraphvizDOT(diagramFilenameDOT string, dpi int) *os.File {
	if *context.verbose {
		fmt.Println("Writing data flow diagram input")
	}
	var dotContent strings.Builder
	dotContent.WriteString("digraph generatedModel { concentrate=false \n")

	// Metadata init ===============================================================================
	tweaks := ""
	if context.parsedModel.DiagramTweakNodesep > 0 {
		tweaks += "\n		nodesep=\"" + strconv.Itoa(context.parsedModel.DiagramTweakNodesep) + "\""
	}
	if context.parsedModel.DiagramTweakRanksep > 0 {
		tweaks += "\n		ranksep=\"" + strconv.Itoa(context.parsedModel.DiagramTweakRanksep) + "\""
	}
	suppressBidirectionalArrows := true
	splines := "ortho"
	if len(context.parsedModel.DiagramTweakEdgeLayout) > 0 {
		switch context.parsedModel.DiagramTweakEdgeLayout {
		case "spline":
			splines = "spline"
			context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "polyline":
			splines = "polyline"
			context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "ortho":
			splines = "ortho"
			suppressBidirectionalArrows = true
		case "curved":
			splines = "curved"
			context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "false":
			splines = "false"
			context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		default:
			panic(errors.New("unknown value for diagram_tweak_suppress_edge_labels (spline, polyline, ortho, curved, false): " +
				context.parsedModel.DiagramTweakEdgeLayout))
		}
	}
	rankdir := "TB"
	if context.parsedModel.DiagramTweakLayoutLeftToRight {
		rankdir = "LR"
	}
	modelTitle := ""
	if context.addModelTitle {
		modelTitle = `label="` + context.parsedModel.Title + `"`
	}
	dotContent.WriteString(`	graph [ ` + modelTitle + `
		labelloc=t
		fontname="Verdana"
		fontsize=40
        outputorder="nodesfirst"
		dpi=` + strconv.Itoa(dpi) + `
		splines=` + splines + `
		rankdir="` + rankdir + `"
` + tweaks + `
	];
	node [
		fontname="Verdana"
		fontsize="20"
	];
	edge [
		shape="none"
		fontname="Verdana"
		fontsize="18"
	];
`)

	// Trust Boundaries ===============================================================================
	var subgraphSnippetsById = make(map[string]string)
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	keys := make([]string, 0)
	for k := range context.parsedModel.TrustBoundaries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		trustBoundary := context.parsedModel.TrustBoundaries[key]
		var snippet strings.Builder
		if len(trustBoundary.TechnicalAssetsInside) > 0 || len(trustBoundary.TrustBoundariesNested) > 0 {
			if context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
				// see https://stackoverflow.com/questions/17247455/how-do-i-add-extra-space-between-clusters?noredirect=1&lq=1
				snippet.WriteString("\n subgraph cluster_space_boundary_for_layout_only_1" + hash(trustBoundary.Id) + " {\n")
				snippet.WriteString(`	graph [
                                              dpi=` + strconv.Itoa(dpi) + `
											  label=<<table border="0" cellborder="0" cellpadding="0" bgcolor="#FFFFFF55"><tr><td><b> </b></td></tr></table>>
											  fontsize="21"
											  style="invis"
											  color="green"
											  fontcolor="green"
											  margin="50.0"
											  penwidth="6.5"
                                              outputorder="nodesfirst"
											];`)
			}
			snippet.WriteString("\n subgraph cluster_" + hash(trustBoundary.Id) + " {\n")
			color, fontColor, bgColor, style, fontname := colors.RgbHexColorTwilight(), colors.RgbHexColorTwilight() /*"#550E0C"*/, "#FAFAFA", "dashed", "Verdana"
			penWidth := 4.5
			if len(trustBoundary.TrustBoundariesNested) > 0 {
				//color, fontColor, style, fontname = colors.Blue, colors.Blue, "dashed", "Verdana"
				penWidth = 5.5
			}
			if len(trustBoundary.ParentTrustBoundaryID(&context.parsedModel)) > 0 {
				bgColor = "#F1F1F1"
			}
			if trustBoundary.Type == types.NetworkPolicyNamespaceIsolation {
				fontColor, bgColor = "#222222", "#DFF4FF"
			}
			if trustBoundary.Type == types.ExecutionEnvironment {
				fontColor, bgColor, style = "#555555", "#FFFFF0", "dotted"
			}
			snippet.WriteString(`	graph [
      dpi=` + strconv.Itoa(dpi) + `
      label=<<table border="0" cellborder="0" cellpadding="0"><tr><td><b>` + trustBoundary.Title + `</b> (` + trustBoundary.Type.String() + `)</td></tr></table>>
      fontsize="21"
      style="` + style + `"
      color="` + color + `"
      bgcolor="` + bgColor + `"
      fontcolor="` + fontColor + `"
      fontname="` + fontname + `"
      penwidth="` + fmt.Sprintf("%f", penWidth) + `"
      forcelabels=true
      outputorder="nodesfirst"
	  margin="50.0"
    ];`)
			snippet.WriteString("\n")
			keys := trustBoundary.TechnicalAssetsInside
			sort.Strings(keys)
			for _, technicalAssetInside := range keys {
				//log.Println("About to add technical asset link to trust boundary: ", technicalAssetInside)
				technicalAsset := context.parsedModel.TechnicalAssets[technicalAssetInside]
				snippet.WriteString(hash(technicalAsset.Id))
				snippet.WriteString(";\n")
			}
			keys = trustBoundary.TrustBoundariesNested
			sort.Strings(keys)
			for _, trustBoundaryNested := range keys {
				//log.Println("About to add nested trust boundary to trust boundary: ", trustBoundaryNested)
				trustBoundaryNested := context.parsedModel.TrustBoundaries[trustBoundaryNested]
				snippet.WriteString("LINK-NEEDS-REPLACED-BY-cluster_" + hash(trustBoundaryNested.Id))
				snippet.WriteString(";\n")
			}
			snippet.WriteString(" }\n\n")
			if context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
				snippet.WriteString(" }\n\n")
			}
		}
		subgraphSnippetsById[hash(trustBoundary.Id)] = snippet.String()
	}
	// here replace links and remove from map after replacement (i.e. move snippet into nested)
	for i := range subgraphSnippetsById {
		re := regexp.MustCompile(`LINK-NEEDS-REPLACED-BY-cluster_([0-9]*);`)
		for {
			matches := re.FindStringSubmatch(subgraphSnippetsById[i])
			if len(matches) > 0 {
				embeddedSnippet := " //nested:" + subgraphSnippetsById[matches[1]]
				subgraphSnippetsById[i] = strings.ReplaceAll(subgraphSnippetsById[i], matches[0], embeddedSnippet)
				subgraphSnippetsById[matches[1]] = "" // to something like remove it
			} else {
				break
			}
		}
	}
	// now write them all
	keys = make([]string, 0)
	for k := range subgraphSnippetsById {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		snippet := subgraphSnippetsById[key]
		dotContent.WriteString(snippet)
	}

	// Technical Assets ===============================================================================
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	// Convert map to slice of values:
	var techAssets []model.TechnicalAsset
	for _, techAsset := range context.parsedModel.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(model.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		dotContent.WriteString(context.makeTechAssetNode(technicalAsset, false))
		dotContent.WriteString("\n")
	}

	// Data Flows (Technical Communication Links) ===============================================================================
	for _, technicalAsset := range techAssets {
		for _, dataFlow := range technicalAsset.CommunicationLinks {
			sourceId := technicalAsset.Id
			targetId := dataFlow.TargetId
			//log.Println("About to add link from", sourceId, "to", targetId, "with id", dataFlow.Id)
			var arrowStyle, arrowColor, readOrWriteHead, readOrWriteTail string
			if dataFlow.Readonly {
				readOrWriteHead = "empty"
				readOrWriteTail = "odot"
			} else {
				readOrWriteHead = "normal"
				readOrWriteTail = "dot"
			}
			dir := "forward"
			if dataFlow.IsBidirectional() {
				if !suppressBidirectionalArrows { // as it does not work as bug in graphviz with ortho: https://gitlab.com/graphviz/graphviz/issues/144
					dir = "both"
				}
			}
			arrowStyle = ` style="` + dataFlow.DetermineArrowLineStyle() + `" penwidth="` + dataFlow.DetermineArrowPenWidth(&context.parsedModel) + `" arrowtail="` + readOrWriteTail + `" arrowhead="` + readOrWriteHead + `" dir="` + dir + `" arrowsize="2.0" `
			arrowColor = ` color="` + dataFlow.DetermineArrowColor(&context.parsedModel) + `"`
			tweaks := ""
			if dataFlow.DiagramTweakWeight > 0 {
				tweaks += " weight=\"" + strconv.Itoa(dataFlow.DiagramTweakWeight) + "\" "
			}

			dotContent.WriteString("\n")
			dotContent.WriteString("  " + hash(sourceId) + " -> " + hash(targetId) +
				` [` + arrowColor + ` ` + arrowStyle + tweaks + ` constraint=` + strconv.FormatBool(dataFlow.DiagramTweakConstraint) + ` `)
			if !context.parsedModel.DiagramTweakSuppressEdgeLabels {
				dotContent.WriteString(` xlabel="` + encode(dataFlow.Protocol.String()) + `" fontcolor="` + dataFlow.DetermineLabelColor(&context.parsedModel) + `" `)
			}
			dotContent.WriteString(" ];\n")
		}
	}

	dotContent.WriteString(context.makeDiagramInvisibleConnectionsTweaks())
	dotContent.WriteString(context.makeDiagramSameRankNodeTweaks())

	dotContent.WriteString("}")

	//fmt.Println(dotContent.String())

	// Write the DOT file
	file, err := os.Create(diagramFilenameDOT)
	checkErr(err)
	defer func() { _ = file.Close() }()
	_, err = fmt.Fprintln(file, dotContent.String())
	checkErr(err)
	return file
}

func (context *Context) makeDiagramSameRankNodeTweaks() string {
	// see https://stackoverflow.com/questions/25734244/how-do-i-place-nodes-on-the-same-level-in-dot
	tweak := ""
	if len(context.parsedModel.DiagramTweakSameRankAssets) > 0 {
		for _, sameRank := range context.parsedModel.DiagramTweakSameRankAssets {
			assetIDs := strings.Split(sameRank, ":")
			if len(assetIDs) > 0 {
				tweak += "{ rank=same; "
				for _, id := range assetIDs {
					context.checkTechnicalAssetExists(id, "diagram tweak same-rank", true)
					if len(context.parsedModel.TechnicalAssets[id].GetTrustBoundaryId(&context.parsedModel)) > 0 {
						panic(errors.New("technical assets (referenced in same rank diagram tweak) are inside trust boundaries: " +
							fmt.Sprintf("%v", context.parsedModel.DiagramTweakSameRankAssets)))
					}
					tweak += " " + hash(id) + "; "
				}
				tweak += " }"
			}
		}
	}
	return tweak
}

func (context *Context) makeDiagramInvisibleConnectionsTweaks() string {
	// see https://stackoverflow.com/questions/2476575/how-to-control-node-placement-in-graphviz-i-e-avoid-edge-crossings
	tweak := ""
	if len(context.parsedModel.DiagramTweakInvisibleConnectionsBetweenAssets) > 0 {
		for _, invisibleConnections := range context.parsedModel.DiagramTweakInvisibleConnectionsBetweenAssets {
			assetIDs := strings.Split(invisibleConnections, ":")
			if len(assetIDs) == 2 {
				context.checkTechnicalAssetExists(assetIDs[0], "diagram tweak connections", true)
				context.checkTechnicalAssetExists(assetIDs[1], "diagram tweak connections", true)
				tweak += "\n" + hash(assetIDs[0]) + " -> " + hash(assetIDs[1]) + " [style=invis]; \n"
			}
		}
	}
	return tweak
}

func (context *Context) DoIt() {
	defer func() {
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if *context.verbose {
				log.Println(err)
			}
			_, _ = os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(2)
		}
	}()
	if len(*context.executeModelMacro) > 0 {
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
	} else {
		if *context.verbose {
			fmt.Println("Writing into output directory:", *context.outputDir)
		}
	}

	context.parseModel()
	introTextRAA := context.applyRAA()
	context.loadCustomRiskRules()
	context.applyRiskGeneration()
	context.applyWildcardRiskTrackingEvaluation()
	context.checkRiskTracking()

	if len(*context.executeModelMacro) > 0 {
		var macroDetails macros.MacroDetails
		switch *context.executeModelMacro {
		case addbuildpipeline.GetMacroDetails().ID:
			macroDetails = addbuildpipeline.GetMacroDetails()
		case addvault.GetMacroDetails().ID:
			macroDetails = addvault.GetMacroDetails()
		case prettyprint.GetMacroDetails().ID:
			macroDetails = prettyprint.GetMacroDetails()
		case removeunusedtags.GetMacroDetails().ID:
			macroDetails = removeunusedtags.GetMacroDetails()
		case seedrisktracking.GetMacroDetails().ID:
			macroDetails = seedrisktracking.GetMacroDetails()
		case seedtags.GetMacroDetails().ID:
			macroDetails = seedtags.GetMacroDetails()
		default:
			log.Fatal("Unknown model macro: ", *context.executeModelMacro)
		}
		fmt.Println("Executing model macro:", macroDetails.ID)
		fmt.Println()
		fmt.Println()
		context.printBorder(len(macroDetails.Title), true)
		fmt.Println(macroDetails.Title)
		context.printBorder(len(macroDetails.Title), true)
		if len(macroDetails.Description) > 0 {
			fmt.Println(macroDetails.Description)
		}
		fmt.Println()
		reader := bufio.NewReader(os.Stdin)
		var err error
		var nextQuestion macros.MacroQuestion
		for {
			switch macroDetails.ID {
			case addbuildpipeline.GetMacroDetails().ID:
				nextQuestion, err = addbuildpipeline.GetNextQuestion(&context.parsedModel)
			case addvault.GetMacroDetails().ID:
				nextQuestion, err = addvault.GetNextQuestion(&context.parsedModel)
			case prettyprint.GetMacroDetails().ID:
				nextQuestion, err = prettyprint.GetNextQuestion()
			case removeunusedtags.GetMacroDetails().ID:
				nextQuestion, err = removeunusedtags.GetNextQuestion()
			case seedrisktracking.GetMacroDetails().ID:
				nextQuestion, err = seedrisktracking.GetNextQuestion()
			case seedtags.GetMacroDetails().ID:
				nextQuestion, err = seedtags.GetNextQuestion()
			}
			checkErr(err)
			if nextQuestion.NoMoreQuestions() {
				break
			}
			fmt.Println()
			context.printBorder(len(nextQuestion.Title), false)
			fmt.Println(nextQuestion.Title)
			context.printBorder(len(nextQuestion.Title), false)
			if len(nextQuestion.Description) > 0 {
				fmt.Println(nextQuestion.Description)
			}
			resultingMultiValueSelection := make([]string, 0)
			if nextQuestion.IsValueConstrained() {
				if nextQuestion.MultiSelect {
					selectedValues := make(map[string]bool)
					for {
						fmt.Println("Please select (multiple executions possible) from the following values (use number to select/deselect):")
						fmt.Println("    0:", "SELECTION PROCESS FINISHED: CONTINUE TO NEXT QUESTION")
						for i, val := range nextQuestion.PossibleAnswers {
							number := i + 1
							padding, selected := "", " "
							if number < 10 {
								padding = " "
							}
							if val, exists := selectedValues[val]; exists && val {
								selected = "*"
							}
							fmt.Println(" "+selected+" "+padding+strconv.Itoa(number)+":", val)
						}
						fmt.Println()
						fmt.Print("Enter number to select/deselect (or 0 when finished): ")
						answer, err := reader.ReadString('\n')
						// convert CRLF to LF
						answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
						checkErr(err)
						if val, err := strconv.Atoi(answer); err == nil { // flip selection
							if val == 0 {
								for key, selected := range selectedValues {
									if selected {
										resultingMultiValueSelection = append(resultingMultiValueSelection, key)
									}
								}
								break
							} else if val > 0 && val <= len(nextQuestion.PossibleAnswers) {
								selectedValues[nextQuestion.PossibleAnswers[val-1]] = !selectedValues[nextQuestion.PossibleAnswers[val-1]]
							}
						}
					}
				} else {
					fmt.Println("Please choose from the following values (enter value directly or use number):")
					for i, val := range nextQuestion.PossibleAnswers {
						number := i + 1
						padding := ""
						if number < 10 {
							padding = " "
						}
						fmt.Println("   "+padding+strconv.Itoa(number)+":", val)
					}
				}
			}
			message := ""
			validResult := true
			if !nextQuestion.IsValueConstrained() || !nextQuestion.MultiSelect {
				fmt.Println()
				fmt.Println("Enter your answer (use 'BACK' to go one step back or 'QUIT' to quit without executing the model macro)")
				fmt.Print("Answer")
				if len(nextQuestion.DefaultAnswer) > 0 {
					fmt.Print(" (default '" + nextQuestion.DefaultAnswer + "')")
				}
				fmt.Print(": ")
				answer, err := reader.ReadString('\n')
				// convert CRLF to LF
				answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
				checkErr(err)
				if len(answer) == 0 && len(nextQuestion.DefaultAnswer) > 0 { // accepting the default
					answer = nextQuestion.DefaultAnswer
				} else if nextQuestion.IsValueConstrained() { // convert number to value
					if val, err := strconv.Atoi(answer); err == nil {
						if val > 0 && val <= len(nextQuestion.PossibleAnswers) {
							answer = nextQuestion.PossibleAnswers[val-1]
						}
					}
				}
				if strings.ToLower(answer) == "quit" {
					fmt.Println("Quitting without executing the model macro")
					return
				} else if strings.ToLower(answer) == "back" {
					switch macroDetails.ID {
					case addbuildpipeline.GetMacroDetails().ID:
						message, validResult, err = addbuildpipeline.GoBack()
					case addvault.GetMacroDetails().ID:
						message, validResult, err = addvault.GoBack()
					case prettyprint.GetMacroDetails().ID:
						message, validResult, err = prettyprint.GoBack()
					case removeunusedtags.GetMacroDetails().ID:
						message, validResult, err = removeunusedtags.GoBack()
					case seedrisktracking.GetMacroDetails().ID:
						message, validResult, err = seedrisktracking.GoBack()
					case seedtags.GetMacroDetails().ID:
						message, validResult, err = seedtags.GoBack()
					}
				} else if len(answer) > 0 { // individual answer
					if nextQuestion.IsValueConstrained() {
						if !nextQuestion.IsMatchingValueConstraint(answer) {
							fmt.Println()
							fmt.Println(">>> INVALID <<<")
							fmt.Println("Answer does not match any allowed value. Please try again:")
							continue
						}
					}
					switch macroDetails.ID {
					case addbuildpipeline.GetMacroDetails().ID:
						message, validResult, err = addbuildpipeline.ApplyAnswer(nextQuestion.ID, answer)
					case addvault.GetMacroDetails().ID:
						message, validResult, err = addvault.ApplyAnswer(nextQuestion.ID, answer)
					case prettyprint.GetMacroDetails().ID:
						message, validResult, err = prettyprint.ApplyAnswer(nextQuestion.ID, answer)
					case removeunusedtags.GetMacroDetails().ID:
						message, validResult, err = removeunusedtags.ApplyAnswer(nextQuestion.ID, answer)
					case seedrisktracking.GetMacroDetails().ID:
						message, validResult, err = seedrisktracking.ApplyAnswer(nextQuestion.ID, answer)
					case seedtags.GetMacroDetails().ID:
						message, validResult, err = seedtags.ApplyAnswer(nextQuestion.ID, answer)
					}
				}
			} else {
				switch macroDetails.ID {
				case addbuildpipeline.GetMacroDetails().ID:
					message, validResult, err = addbuildpipeline.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case addvault.GetMacroDetails().ID:
					message, validResult, err = addvault.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case prettyprint.GetMacroDetails().ID:
					message, validResult, err = prettyprint.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case removeunusedtags.GetMacroDetails().ID:
					message, validResult, err = removeunusedtags.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case seedrisktracking.GetMacroDetails().ID:
					message, validResult, err = seedrisktracking.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case seedtags.GetMacroDetails().ID:
					message, validResult, err = seedtags.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				}
			}
			checkErr(err)
			if !validResult {
				fmt.Println()
				fmt.Println(">>> INVALID <<<")
			}
			fmt.Println(message)
			fmt.Println()
		}
		for {
			fmt.Println()
			fmt.Println()
			fmt.Println("#################################################################")
			fmt.Println("Do you want to execute the model macro (updating the model file)?")
			fmt.Println("#################################################################")
			fmt.Println()
			fmt.Println("The following changes will be applied:")
			var changes []string
			message := ""
			validResult := true
			var err error
			switch macroDetails.ID {
			case addbuildpipeline.GetMacroDetails().ID:
				changes, message, validResult, err = addbuildpipeline.GetFinalChangeImpact(&context.modelInput, &context.parsedModel)
			case addvault.GetMacroDetails().ID:
				changes, message, validResult, err = addvault.GetFinalChangeImpact(&context.modelInput, &context.parsedModel)
			case prettyprint.GetMacroDetails().ID:
				changes, message, validResult, err = prettyprint.GetFinalChangeImpact(&context.modelInput)
			case removeunusedtags.GetMacroDetails().ID:
				changes, message, validResult, err = removeunusedtags.GetFinalChangeImpact(&context.modelInput)
			case seedrisktracking.GetMacroDetails().ID:
				changes, message, validResult, err = seedrisktracking.GetFinalChangeImpact(&context.modelInput)
			case seedtags.GetMacroDetails().ID:
				changes, message, validResult, err = seedtags.GetFinalChangeImpact(&context.modelInput)
			}
			checkErr(err)
			for _, change := range changes {
				fmt.Println(" -", change)
			}
			if !validResult {
				fmt.Println()
				fmt.Println(">>> INVALID <<<")
			}
			fmt.Println()
			fmt.Println(message)
			fmt.Println()
			fmt.Print("Apply these changes to the model file?\nType Yes or No: ")
			answer, err := reader.ReadString('\n')
			// convert CRLF to LF
			answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
			checkErr(err)
			answer = strings.ToLower(answer)
			fmt.Println()
			if answer == "yes" || answer == "y" {
				message := ""
				validResult := true
				var err error
				switch macroDetails.ID {
				case addbuildpipeline.GetMacroDetails().ID:
					message, validResult, err = addbuildpipeline.Execute(&context.modelInput, &context.parsedModel)
				case addvault.GetMacroDetails().ID:
					message, validResult, err = addvault.Execute(&context.modelInput, &context.parsedModel)
				case prettyprint.GetMacroDetails().ID:
					message, validResult, err = prettyprint.Execute(&context.modelInput)
				case removeunusedtags.GetMacroDetails().ID:
					message, validResult, err = removeunusedtags.Execute(&context.modelInput, &context.parsedModel)
				case seedrisktracking.GetMacroDetails().ID:
					message, validResult, err = seedrisktracking.Execute(&context.parsedModel, &context.modelInput)
				case seedtags.GetMacroDetails().ID:
					message, validResult, err = seedtags.Execute(&context.modelInput, &context.parsedModel)
				}
				checkErr(err)
				if !validResult {
					fmt.Println()
					fmt.Println(">>> INVALID <<<")
				}
				fmt.Println(message)
				fmt.Println()
				backupFilename := *context.modelFilename + ".backup"
				fmt.Println("Creating backup model file:", backupFilename) // TODO add random files in /dev/shm space?
				_, err = copyFile(*context.modelFilename, backupFilename)
				checkErr(err)
				fmt.Println("Updating model")
				yamlBytes, err := yaml.Marshal(context.modelInput)
				checkErr(err)
				/*
					yamlBytes = model.ReformatYAML(yamlBytes)
				*/
				fmt.Println("Writing model file:", *context.modelFilename)
				err = os.WriteFile(*context.modelFilename, yamlBytes, 0400)
				checkErr(err)
				fmt.Println("Model file successfully updated")
				return
			} else if answer == "no" || answer == "n" {
				fmt.Println("Quitting without executing the model macro")
				return
			}
		}
	}

	renderDataFlowDiagram := *context.generateDataFlowDiagram
	renderDataAssetDiagram := *context.generateDataAssetDiagram
	renderRisksJSON := *context.generateRisksJSON
	renderTechnicalAssetsJSON := *context.generateTechnicalAssetsJSON
	renderStatsJSON := *context.generateStatsJSON
	renderRisksExcel := *context.generateRisksExcel
	renderTagsExcel := *context.generateTagsExcel
	renderPDF := *context.generateReportPDF
	if renderPDF { // as the PDF report includes both diagrams
		renderDataFlowDiagram, renderDataAssetDiagram = true, true
	}

	// Data-flow Diagram rendering
	if renderDataFlowDiagram {
		gvFile := filepath.Join(*context.outputDir, context.dataFlowDiagramFilenameDOT)
		if !context.keepDiagramSourceFiles {
			tmpFileGV, err := os.CreateTemp(*context.tempFolder, context.dataFlowDiagramFilenameDOT)
			checkErr(err)
			gvFile = tmpFileGV.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile := context.writeDataFlowDiagramGraphvizDOT(gvFile, *context.diagramDPI)
		context.renderDataFlowDiagramGraphvizImage(dotFile, *context.outputDir)
	}
	// Data Asset Diagram rendering
	if renderDataAssetDiagram {
		gvFile := filepath.Join(*context.outputDir, context.dataAssetDiagramFilenameDOT)
		if !context.keepDiagramSourceFiles {
			tmpFile, err := os.CreateTemp(*context.tempFolder, context.dataAssetDiagramFilenameDOT)
			checkErr(err)
			gvFile = tmpFile.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile := context.writeDataAssetDiagramGraphvizDOT(gvFile, *context.diagramDPI)
		context.renderDataAssetDiagramGraphvizImage(dotFile, *context.outputDir)
	}

	// risks as risks json
	if renderRisksJSON {
		if *context.verbose {
			fmt.Println("Writing risks json")
		}
		report.WriteRisksJSON(&context.parsedModel, filepath.Join(*context.outputDir, context.jsonRisksFilename))
	}

	// technical assets json
	if renderTechnicalAssetsJSON {
		if *context.verbose {
			fmt.Println("Writing technical assets json")
		}
		report.WriteTechnicalAssetsJSON(&context.parsedModel, filepath.Join(*context.outputDir, context.jsonTechnicalAssetsFilename))
	}

	// risks as risks json
	if renderStatsJSON {
		if *context.verbose {
			fmt.Println("Writing stats json")
		}
		report.WriteStatsJSON(&context.parsedModel, filepath.Join(*context.outputDir, context.jsonStatsFilename))
	}

	// risks Excel
	if renderRisksExcel {
		if *context.verbose {
			fmt.Println("Writing risks excel")
		}
		report.WriteRisksExcelToFile(&context.parsedModel, filepath.Join(*context.outputDir, context.excelRisksFilename))
	}

	// tags Excel
	if renderTagsExcel {
		if *context.verbose {
			fmt.Println("Writing tags excel")
		}
		report.WriteTagsExcelToFile(&context.parsedModel, filepath.Join(*context.outputDir, context.excelTagsFilename))
	}

	if renderPDF {
		// hash the YAML input file
		f, err := os.Open(*context.modelFilename)
		checkErr(err)
		defer func() { _ = f.Close() }()
		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			panic(err)
		}
		modelHash := hex.EncodeToString(hasher.Sum(nil))
		// report PDF
		if *context.verbose {
			fmt.Println("Writing report pdf")
		}
		report.WriteReportPDF(filepath.Join(*context.outputDir, context.reportFilename),
			filepath.Join(*context.appFolder, *context.templateFilename),
			filepath.Join(*context.outputDir, context.dataFlowDiagramFilenamePNG),
			filepath.Join(*context.outputDir, context.dataAssetDiagramFilenamePNG),
			*context.modelFilename,
			*context.skipRiskRules,
			context.buildTimestamp,
			modelHash,
			introTextRAA,
			context.customRiskRules,
			*context.tempFolder,
			&context.parsedModel)
	}
}

func (context *Context) printBorder(length int, bold bool) {
	char := "-"
	if bold {
		char = "="
	}
	for i := 1; i <= length; i++ {
		fmt.Print(char)
	}
	fmt.Println()
}

func (context *Context) applyRAA() string {
	if *context.verbose {
		fmt.Println("Applying RAA calculation:", *context.raaPlugin)
	}

	raa := *context.raaPlugin
	runner, loadError := new(run.Runner).Load(filepath.Join(*context.binFolder, *context.raaPlugin))
	if loadError != nil {
		raa = strings.TrimSuffix(raa, filepath.Ext(raa))
		runner, loadError = new(run.Runner).Load(filepath.Join(*context.binFolder, raa))
		if loadError != nil {
			fmt.Printf("WARNING: raa %q not loaded: %v\n", *context.raaPlugin, loadError)
			return ""
		}
	}

	runError := runner.Run(context.parsedModel, &context.parsedModel)
	if runError != nil {
		fmt.Printf("WARNING: raa %q not applied: %v\n", *context.raaPlugin, runError)
		return ""
	}

	return runner.ErrorOutput
}

func (context *Context) loadCustomRiskRules() {
	context.customRiskRules = make(map[string]*model.CustomRisk)
	if len(*context.riskRulesPlugins) > 0 {
		if *context.verbose {
			fmt.Println("Loading custom risk rules:", *context.riskRulesPlugins)
		}

		for _, pluginFile := range strings.Split(*context.riskRulesPlugins, ",") {
			if len(pluginFile) > 0 {
				runner, loadError := new(run.Runner).Load(pluginFile)
				if loadError != nil {
					log.Fatalf("WARNING: Custom risk rule %q not loaded: %v\n", pluginFile, loadError)
				}

				risk := new(model.CustomRisk)
				runError := runner.Run(nil, &risk, "-get-info")
				if runError != nil {
					log.Fatalf("WARNING: Failed to get ID for custom risk rule %q: %v\n", pluginFile, runError)
				}

				risk.Runner = runner
				context.customRiskRules[risk.ID] = risk
				if *context.verbose {
					fmt.Println("Custom risk rule loaded:", risk.ID)
				}
			}
		}

		if *context.verbose {
			fmt.Println("Loaded custom risk rules:", len(context.customRiskRules))
		}
	}
}

func (context *Context) checkIdSyntax(id string) {
	validIdSyntax := regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)
	if !validIdSyntax.MatchString(id) {
		panic(errors.New("invalid id syntax used (only letters, numbers, and hyphen allowed): " + id))
	}
}

func (context *Context) analyze(ginContext *gin.Context) {
	context.execute(ginContext, false)
}

func (context *Context) check(ginContext *gin.Context) {
	_, ok := context.execute(ginContext, true)
	if ok {
		ginContext.JSON(http.StatusOK, gin.H{
			"message": "model is ok",
		})
	}
}

func (context *Context) execute(ginContext *gin.Context, dryRun bool) (yamlContent []byte, ok bool) {
	defer func() {
		var err error
		if r := recover(); r != nil {
			context.errorCount++
			err = r.(error)
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()

	dpi, err := strconv.Atoi(ginContext.DefaultQuery("dpi", strconv.Itoa(context.defaultGraphvizDPI)))
	checkErr(err)

	fileUploaded, header, err := ginContext.Request.FormFile("file")
	checkErr(err)

	if header.Size > 50000000 {
		msg := "maximum model upload file size exceeded (denial-of-service protection)"
		log.Println(msg)
		ginContext.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": msg,
		})
		return yamlContent, false
	}

	filenameUploaded := strings.TrimSpace(header.Filename)

	tmpInputDir, err := os.MkdirTemp(*context.tempFolder, "threagile-input-")
	checkErr(err)
	defer func() { _ = os.RemoveAll(tmpInputDir) }()

	tmpModelFile, err := os.CreateTemp(tmpInputDir, "threagile-model-*")
	checkErr(err)
	defer func() { _ = os.Remove(tmpModelFile.Name()) }()
	_, err = io.Copy(tmpModelFile, fileUploaded)
	checkErr(err)

	yamlFile := tmpModelFile.Name()

	if strings.ToLower(filepath.Ext(filenameUploaded)) == ".zip" {
		// unzip first (including the resources like images etc.)
		if *context.verbose {
			fmt.Println("Decompressing uploaded archive")
		}
		filenamesUnzipped, err := context.unzip(tmpModelFile.Name(), tmpInputDir)
		checkErr(err)
		found := false
		for _, name := range filenamesUnzipped {
			if strings.ToLower(filepath.Ext(name)) == ".yaml" {
				yamlFile = name
				found = true
				break
			}
		}
		if !found {
			panic(errors.New("no yaml file found in uploaded archive"))
		}
	}

	tmpOutputDir, err := os.MkdirTemp(*context.tempFolder, "threagile-output-")
	checkErr(err)
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()

	tmpResultFile, err := os.CreateTemp(*context.tempFolder, "threagile-result-*.zip")
	checkErr(err)
	defer func() { _ = os.Remove(tmpResultFile.Name()) }()

	if dryRun {
		context.doItViaRuntimeCall(yamlFile, tmpOutputDir, false, false, false, false, false, true, true, true, 40)
	} else {
		context.doItViaRuntimeCall(yamlFile, tmpOutputDir, true, true, true, true, true, true, true, true, dpi)
	}
	checkErr(err)

	yamlContent, err = os.ReadFile(yamlFile)
	checkErr(err)
	err = os.WriteFile(filepath.Join(tmpOutputDir, context.inputFile), yamlContent, 0400)
	checkErr(err)

	if !dryRun {
		files := []string{
			filepath.Join(tmpOutputDir, context.inputFile),
			filepath.Join(tmpOutputDir, context.dataFlowDiagramFilenamePNG),
			filepath.Join(tmpOutputDir, context.dataAssetDiagramFilenamePNG),
			filepath.Join(tmpOutputDir, context.reportFilename),
			filepath.Join(tmpOutputDir, context.excelRisksFilename),
			filepath.Join(tmpOutputDir, context.excelTagsFilename),
			filepath.Join(tmpOutputDir, context.jsonRisksFilename),
			filepath.Join(tmpOutputDir, context.jsonTechnicalAssetsFilename),
			filepath.Join(tmpOutputDir, context.jsonStatsFilename),
		}
		if context.keepDiagramSourceFiles {
			files = append(files, filepath.Join(tmpOutputDir, context.dataFlowDiagramFilenameDOT))
			files = append(files, filepath.Join(tmpOutputDir, context.dataAssetDiagramFilenameDOT))
		}
		err = context.zipFiles(tmpResultFile.Name(), files)
		checkErr(err)
		if *context.verbose {
			log.Println("Streaming back result file: " + tmpResultFile.Name())
		}
		ginContext.FileAttachment(tmpResultFile.Name(), "threagile-result.zip")
	}
	context.successCount++
	return yamlContent, true
}

// ultimately to avoid any in-process memory and/or data leaks by the used third party libs like PDF generation: exec and quit
func (context *Context) doItViaRuntimeCall(modelFile string, outputDir string,
	generateDataFlowDiagram, generateDataAssetDiagram, generateReportPdf, generateRisksExcel, generateTagsExcel, generateRisksJSON, generateTechnicalAssetsJSON, generateStatsJSON bool,
	dpi int) {
	// Remember to also add the same args to the exec based sub-process calls!
	var cmd *exec.Cmd
	args := []string{"-model", modelFile, "-output", outputDir, "-execute-model-macro", *context.executeModelMacro, "-raa-run", *context.raaPlugin, "-custom-risk-rules-plugins", *context.riskRulesPlugins, "-skip-risk-rules", *context.skipRiskRules, "-diagram-dpi", strconv.Itoa(dpi)}
	if *context.verbose {
		args = append(args, "-verbose")
	}
	if *context.ignoreOrphanedRiskTracking { // TODO why add all them as arguments, when they are also variables on outer level?
		args = append(args, "-ignore-orphaned-risk-tracking")
	}
	if generateDataFlowDiagram {
		args = append(args, "-generate-data-flow-diagram")
	}
	if generateDataAssetDiagram {
		args = append(args, "-generate-data-asset-diagram")
	}
	if generateReportPdf {
		args = append(args, "-generate-report-pdf")
	}
	if generateRisksExcel {
		args = append(args, "-generate-risks-excel")
	}
	if generateTagsExcel {
		args = append(args, "-generate-tags-excel")
	}
	if generateRisksJSON {
		args = append(args, "-generate-risks-json")
	}
	if generateTechnicalAssetsJSON {
		args = append(args, "-generate-technical-assets-json")
	}
	if generateStatsJSON {
		args = append(args, "-generate-stats-json")
	}
	self := os.Args[0]
	cmd = exec.Command(self, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic(errors.New(string(out)))
	} else {
		if *context.verbose && len(out) > 0 {
			fmt.Println("---")
			fmt.Print(string(out))
			fmt.Println("---")
		}
	}
}

func (context *Context) StartServer() {
	router := gin.Default()
	router.LoadHTMLGlob("server/static/*.html") // <==
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.HEAD("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.StaticFile("/threagile.png", "server/static/threagile.png") // <==
	router.StaticFile("/site.webmanifest", "server/static/site.webmanifest")
	router.StaticFile("/favicon.ico", "server/static/favicon.ico")
	router.StaticFile("/favicon-32x32.png", "server/static/favicon-32x32.png")
	router.StaticFile("/favicon-16x16.png", "server/static/favicon-16x16.png")
	router.StaticFile("/apple-touch-icon.png", "server/static/apple-touch-icon.png")
	router.StaticFile("/android-chrome-512x512.png", "server/static/android-chrome-512x512.png")
	router.StaticFile("/android-chrome-192x192.png", "server/static/android-chrome-192x192.png")

	router.StaticFile("/schema.json", "schema.json")
	router.StaticFile("/live-templates.txt", "live-templates.txt")
	router.StaticFile("/openapi.yaml", "openapi.yaml")
	router.StaticFile("/swagger-ui/", "server/static/swagger-ui/index.html")
	router.StaticFile("/swagger-ui/index.html", "server/static/swagger-ui/index.html")
	router.StaticFile("/swagger-ui/oauth2-redirect.html", "server/static/swagger-ui/oauth2-redirect.html")
	router.StaticFile("/swagger-ui/swagger-ui.css", "server/static/swagger-ui/swagger-ui.css")
	router.StaticFile("/swagger-ui/swagger-ui.js", "server/static/swagger-ui/swagger-ui.js")
	router.StaticFile("/swagger-ui/swagger-ui-bundle.js", "server/static/swagger-ui/swagger-ui-bundle.js")
	router.StaticFile("/swagger-ui/swagger-ui-standalone-preset.js", "server/static/swagger-ui/swagger-ui-standalone-preset.js") // <==

	router.GET("/threagile-example-model.yaml", context.exampleFile)
	router.GET("/threagile-stub-model.yaml", context.stubFile)

	router.GET("/meta/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	router.GET("/meta/version", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"version":         docs.ThreagileVersion,
			"build_timestamp": context.buildTimestamp,
		})
	})
	router.GET("/meta/types", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"quantity":                     context.arrayOfStringValues(types.QuantityValues()),
			"confidentiality":              context.arrayOfStringValues(types.ConfidentialityValues()),
			"criticality":                  context.arrayOfStringValues(types.CriticalityValues()),
			"technical_asset_type":         context.arrayOfStringValues(types.TechnicalAssetTypeValues()),
			"technical_asset_size":         context.arrayOfStringValues(types.TechnicalAssetSizeValues()),
			"authorization":                context.arrayOfStringValues(types.AuthorizationValues()),
			"authentication":               context.arrayOfStringValues(types.AuthenticationValues()),
			"usage":                        context.arrayOfStringValues(types.UsageValues()),
			"encryption":                   context.arrayOfStringValues(types.EncryptionStyleValues()),
			"data_format":                  context.arrayOfStringValues(types.DataFormatValues()),
			"protocol":                     context.arrayOfStringValues(types.ProtocolValues()),
			"technical_asset_technology":   context.arrayOfStringValues(types.TechnicalAssetTechnologyValues()),
			"technical_asset_machine":      context.arrayOfStringValues(types.TechnicalAssetMachineValues()),
			"trust_boundary_type":          context.arrayOfStringValues(types.TrustBoundaryTypeValues()),
			"data_breach_probability":      context.arrayOfStringValues(types.DataBreachProbabilityValues()),
			"risk_severity":                context.arrayOfStringValues(types.RiskSeverityValues()),
			"risk_exploitation_likelihood": context.arrayOfStringValues(types.RiskExploitationLikelihoodValues()),
			"risk_exploitation_impact":     context.arrayOfStringValues(types.RiskExploitationImpactValues()),
			"risk_function":                context.arrayOfStringValues(types.RiskFunctionValues()),
			"risk_status":                  context.arrayOfStringValues(types.RiskStatusValues()),
			"stride":                       context.arrayOfStringValues(types.STRIDEValues()),
		})
	})

	// TODO router.GET("/meta/risk-rules", listRiskRules)
	// TODO router.GET("/meta/model-macros", listModelMacros)

	router.GET("/meta/stats", context.stats)

	router.POST("/direct/analyze", context.analyze)
	router.POST("/direct/check", context.check)
	router.GET("/direct/stub", context.stubFile)

	router.POST("/auth/keys", context.createKey)
	router.DELETE("/auth/keys", context.deleteKey)
	router.POST("/auth/tokens", context.createToken)
	router.DELETE("/auth/tokens", context.deleteToken)

	router.POST("/models", context.createNewModel)
	router.GET("/models", context.listModels)
	router.DELETE("/models/:model-id", context.deleteModel)
	router.GET("/models/:model-id", context.getModel)
	router.PUT("/models/:model-id", context.importModel)
	router.GET("/models/:model-id/data-flow-diagram", context.streamDataFlowDiagram)
	router.GET("/models/:model-id/data-asset-diagram", context.streamDataAssetDiagram)
	router.GET("/models/:model-id/report-pdf", context.streamReportPDF)
	router.GET("/models/:model-id/risks-excel", context.streamRisksExcel)
	router.GET("/models/:model-id/tags-excel", context.streamTagsExcel)
	router.GET("/models/:model-id/risks", context.streamRisksJSON)
	router.GET("/models/:model-id/technical-assets", context.streamTechnicalAssetsJSON)
	router.GET("/models/:model-id/stats", context.streamStatsJSON)
	router.GET("/models/:model-id/analysis", context.analyzeModelOnServerDirectly)

	router.GET("/models/:model-id/cover", context.getCover)
	router.PUT("/models/:model-id/cover", context.setCover)
	router.GET("/models/:model-id/overview", context.getOverview)
	router.PUT("/models/:model-id/overview", context.setOverview)
	//router.GET("/models/:model-id/questions", getQuestions)
	//router.PUT("/models/:model-id/questions", setQuestions)
	router.GET("/models/:model-id/abuse-cases", context.getAbuseCases)
	router.PUT("/models/:model-id/abuse-cases", context.setAbuseCases)
	router.GET("/models/:model-id/security-requirements", context.getSecurityRequirements)
	router.PUT("/models/:model-id/security-requirements", context.setSecurityRequirements)
	//router.GET("/models/:model-id/tags", getTags)
	//router.PUT("/models/:model-id/tags", setTags)

	router.GET("/models/:model-id/data-assets", context.getDataAssets)
	router.POST("/models/:model-id/data-assets", context.createNewDataAsset)
	router.GET("/models/:model-id/data-assets/:data-asset-id", context.getDataAsset)
	router.PUT("/models/:model-id/data-assets/:data-asset-id", context.setDataAsset)
	router.DELETE("/models/:model-id/data-assets/:data-asset-id", context.deleteDataAsset)

	router.GET("/models/:model-id/trust-boundaries", context.getTrustBoundaries)
	//	router.POST("/models/:model-id/trust-boundaries", createNewTrustBoundary)
	//	router.GET("/models/:model-id/trust-boundaries/:trust-boundary-id", getTrustBoundary)
	//	router.PUT("/models/:model-id/trust-boundaries/:trust-boundary-id", setTrustBoundary)
	//	router.DELETE("/models/:model-id/trust-boundaries/:trust-boundary-id", deleteTrustBoundary)

	router.GET("/models/:model-id/shared-runtimes", context.getSharedRuntimes)
	router.POST("/models/:model-id/shared-runtimes", context.createNewSharedRuntime)
	router.GET("/models/:model-id/shared-runtimes/:shared-runtime-id", context.getSharedRuntime)
	router.PUT("/models/:model-id/shared-runtimes/:shared-runtime-id", context.setSharedRuntime)
	router.DELETE("/models/:model-id/shared-runtimes/:shared-runtime-id", context.deleteSharedRuntime)

	fmt.Println("Threagile server running...")
	_ = router.Run(":" + strconv.Itoa(*context.serverPort)) // listen and serve on 0.0.0.0:8080 or whatever port was specified
}

func (context *Context) exampleFile(ginContext *gin.Context) {
	example, err := os.ReadFile(filepath.Join(*context.appFolder, "threagile-example-model.yaml"))
	checkErr(err)
	ginContext.Data(http.StatusOK, gin.MIMEYAML, example)
}

func (context *Context) stubFile(ginContext *gin.Context) {
	stub, err := os.ReadFile(filepath.Join(*context.appFolder, "threagile-stub-model.yaml"))
	checkErr(err)
	ginContext.Data(http.StatusOK, gin.MIMEYAML, context.addSupportedTags(stub)) // TODO use also the MIMEYAML way of serving YAML in model export?
}

func (context *Context) addSupportedTags(input []byte) []byte {
	// add distinct tags as "tags_available"
	supportedTags := make(map[string]bool)
	for _, customRule := range context.customRiskRules {
		for _, tag := range customRule.Tags {
			supportedTags[strings.ToLower(tag)] = true
		}
	}
	for _, tag := range accidentalsecretleak.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range codebackdooring.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range containerbaseimagebackdooring.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range containerplatformescape.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range crosssiterequestforgery.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range crosssitescripting.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range dosriskyaccessacrosstrustboundary.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range incompletemodel.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range ldapinjection.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingauthentication.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingauthenticationsecondfactor.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingbuildinfrastructure.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingcloudhardening.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingfilevalidation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missinghardening.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingidentitypropagation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingidentityproviderisolation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingidentitystore.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingnetworksegmentation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingvault.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingvaultisolation.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range missingwaf.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range mixedtargetsonsharedruntime.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range pathtraversal.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range pushinsteadofpulldeployment.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range searchqueryinjection.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range serversiderequestforgery.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range serviceregistrypoisoning.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range sqlnosqlinjection.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range uncheckeddeployment.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unencryptedasset.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unencryptedcommunication.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unguardedaccessfrominternet.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unguardeddirectdatastoreaccess.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessarycommunicationlink.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessarydataasset.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessarydatatransfer.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range unnecessarytechnicalasset.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range untrusteddeserialization.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range wrongcommunicationlinkcontent.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range wrongtrustboundarycontent.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	for _, tag := range xmlexternalentity.SupportedTags() {
		supportedTags[strings.ToLower(tag)] = true
	}
	tags := make([]string, 0, len(supportedTags))
	for t := range supportedTags {
		tags = append(tags, t)
	}
	if len(tags) == 0 {
		return input
	}
	sort.Strings(tags)
	if *context.verbose {
		fmt.Print("Supported tags of all risk rules: ")
		for i, tag := range tags {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(tag)
		}
		fmt.Println()
	}
	replacement := "tags_available:"
	for _, tag := range tags {
		replacement += "\n  - " + tag
	}
	return []byte(strings.Replace(string(input), "tags_available:", replacement, 1))
}

var mapFolderNameToTokenHash = make(map[string]string)

const keySize = 32

func (context *Context) createToken(ginContext *gin.Context) {
	folderName, key, ok := context.checkKeyToFolderName(ginContext)
	if !ok {
		return
	}
	context.globalLock.Lock()
	defer context.globalLock.Unlock()
	if tokenHash, exists := mapFolderNameToTokenHash[folderName]; exists {
		// invalidate previous token
		delete(mapTokenHashToTimeoutStruct, tokenHash)
	}
	// create a strong random 256 bit value (used to xor)
	xorBytesArr := make([]byte, keySize)
	n, err := rand.Read(xorBytesArr[:])
	if n != keySize || err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create token",
		})
		return
	}
	now := time.Now().UnixNano()
	token := xor(key, xorBytesArr)
	tokenHash := hashSHA256(token)
	housekeepingTokenMaps()
	mapTokenHashToTimeoutStruct[tokenHash] = timeoutStruct{
		xorRand:              xorBytesArr,
		createdNanoTime:      now,
		lastAccessedNanoTime: now,
	}
	mapFolderNameToTokenHash[folderName] = tokenHash
	ginContext.JSON(http.StatusCreated, gin.H{
		"token": base64.RawURLEncoding.EncodeToString(token[:]),
	})
}

type tokenHeader struct {
	Token string `header:"token"`
}

func (context *Context) deleteToken(ginContext *gin.Context) {
	header := tokenHeader{}
	if err := ginContext.ShouldBindHeader(&header); err != nil {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Token))
	if len(token) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	context.globalLock.Lock()
	defer context.globalLock.Unlock()
	deleteTokenHashFromMaps(hashSHA256(token))
	ginContext.JSON(http.StatusOK, gin.H{
		"message": "token deleted",
	})
}

type responseType int

const (
	dataFlowDiagram responseType = iota
	dataAssetDiagram
	reportPDF
	risksExcel
	tagsExcel
	risksJSON
	technicalAssetsJSON
	statsJSON
)

func (context *Context) streamDataFlowDiagram(ginContext *gin.Context) {
	context.streamResponse(ginContext, dataFlowDiagram)
}

func (context *Context) streamDataAssetDiagram(ginContext *gin.Context) {
	context.streamResponse(ginContext, dataAssetDiagram)
}

func (context *Context) streamReportPDF(ginContext *gin.Context) {
	context.streamResponse(ginContext, reportPDF)
}

func (context *Context) streamRisksExcel(ginContext *gin.Context) {
	context.streamResponse(ginContext, risksExcel)
}

func (context *Context) streamTagsExcel(ginContext *gin.Context) {
	context.streamResponse(ginContext, tagsExcel)
}

func (context *Context) streamRisksJSON(ginContext *gin.Context) {
	context.streamResponse(ginContext, risksJSON)
}

func (context *Context) streamTechnicalAssetsJSON(ginContext *gin.Context) {
	context.streamResponse(ginContext, technicalAssetsJSON)
}

func (context *Context) streamStatsJSON(ginContext *gin.Context) {
	context.streamResponse(ginContext, statsJSON)
}

func (context *Context) streamResponse(ginContext *gin.Context, responseType responseType) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer func() {
		context.unlockFolder(folderNameOfKey)
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if *context.verbose {
				log.Println(err)
			}
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()
	dpi, err := strconv.Atoi(ginContext.DefaultQuery("dpi", strconv.Itoa(context.defaultGraphvizDPI)))
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return
	}
	_, yamlText, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return
	}
	tmpModelFile, err := os.CreateTemp(*context.tempFolder, "threagile-render-*")
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.Remove(tmpModelFile.Name()) }()
	tmpOutputDir, err := os.MkdirTemp(*context.tempFolder, "threagile-render-")
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()
	err = os.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400)
	if responseType == dataFlowDiagram {
		context.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, true, false, false, false, false, false, false, false, dpi)
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.File(filepath.Join(tmpOutputDir, context.dataFlowDiagramFilenamePNG))
	} else if responseType == dataAssetDiagram {
		context.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, true, false, false, false, false, false, false, dpi)
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.File(filepath.Join(tmpOutputDir, context.dataAssetDiagramFilenamePNG))
	} else if responseType == reportPDF {
		context.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, true, false, false, false, false, false, dpi)
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.FileAttachment(filepath.Join(tmpOutputDir, context.reportFilename), context.reportFilename)
	} else if responseType == risksExcel {
		context.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, true, false, false, false, false, dpi)
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.FileAttachment(filepath.Join(tmpOutputDir, context.excelRisksFilename), context.excelRisksFilename)
	} else if responseType == tagsExcel {
		context.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, true, false, false, false, dpi)
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.FileAttachment(filepath.Join(tmpOutputDir, context.excelTagsFilename), context.excelTagsFilename)
	} else if responseType == risksJSON {
		context.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, false, true, false, false, dpi)
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		jsonData, err := os.ReadFile(filepath.Join(tmpOutputDir, context.jsonRisksFilename))
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.Data(http.StatusOK, "application/json", jsonData) // stream directly with JSON content-type in response instead of file download
	} else if responseType == technicalAssetsJSON {
		context.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, false, true, true, false, dpi)
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		jsonData, err := os.ReadFile(filepath.Join(tmpOutputDir, context.jsonTechnicalAssetsFilename))
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.Data(http.StatusOK, "application/json", jsonData) // stream directly with JSON content-type in response instead of file download
	} else if responseType == statsJSON {
		context.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, false, false, false, true, dpi)
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		jsonData, err := os.ReadFile(filepath.Join(tmpOutputDir, context.jsonStatsFilename))
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.Data(http.StatusOK, "application/json", jsonData) // stream directly with JSON content-type in response instead of file download
	}
}

// fully replaces threagile.yaml in sub-folder given by UUID
func (context *Context) importModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)

	aUuid := ginContext.Param("model-id") // UUID is syntactically validated in readModel+checkModelFolder (next line) via uuid.Parse(modelUUID)
	_, _, ok = context.readModel(ginContext, aUuid, key, folderNameOfKey)
	if ok {
		// first analyze it simply by executing the full risk process (just discard the result) to ensure that everything would work
		yamlContent, ok := context.execute(ginContext, true)
		if ok {
			// if we're here, then no problem was raised, so ok to proceed
			ok = context.writeModelYAML(ginContext, string(yamlContent), key, context.folderNameForModel(folderNameOfKey, aUuid), "Model Import", false)
			if ok {
				ginContext.JSON(http.StatusCreated, gin.H{
					"message": "model imported",
				})
			}
		}
	}
}

func (context *Context) stats(ginContext *gin.Context) {
	keyCount, modelCount := 0, 0
	keyFolders, err := os.ReadDir(filepath.Join(*context.serverFolder, context.keyDir))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to collect stats",
		})
		return
	}
	for _, keyFolder := range keyFolders {
		if len(keyFolder.Name()) == 128 { // it's a sha512 token hash probably, so count it as token folder for the stats
			keyCount++
			modelFolders, err := os.ReadDir(filepath.Join(*context.serverFolder, context.keyDir, keyFolder.Name()))
			if err != nil {
				log.Println(err)
				ginContext.JSON(http.StatusInternalServerError, gin.H{
					"error": "unable to collect stats",
				})
				return
			}
			for _, modelFolder := range modelFolders {
				if len(modelFolder.Name()) == 36 { // it's a uuid model folder probably, so count it as model folder for the stats
					modelCount++
				}
			}
		}
	}
	// TODO collect and deliver more stats (old model count?) and health info
	ginContext.JSON(http.StatusOK, gin.H{
		"key_count":     keyCount,
		"model_count":   modelCount,
		"success_count": context.successCount,
		"error_count":   context.errorCount,
	})
}

func (context *Context) getDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				ginContext.JSON(http.StatusOK, gin.H{
					title: dataAsset,
				})
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func (context *Context) deleteDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		referencesDeleted := false
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				// also remove all usages of this data asset !!
				for _, techAsset := range modelInput.TechnicalAssets {
					if techAsset.DataAssetsProcessed != nil {
						for i, parsedChangeCandidateAsset := range techAsset.DataAssetsProcessed {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.DataAssetsProcessed[i:], techAsset.DataAssetsProcessed[i+1:])                         // Shift a[i+1:] left one index.
								techAsset.DataAssetsProcessed[len(techAsset.DataAssetsProcessed)-1] = ""                             // Erase last element (write zero value).
								techAsset.DataAssetsProcessed = techAsset.DataAssetsProcessed[:len(techAsset.DataAssetsProcessed)-1] // Truncate slice.
							}
						}
					}
					if techAsset.DataAssetsStored != nil {
						for i, parsedChangeCandidateAsset := range techAsset.DataAssetsStored {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.DataAssetsStored[i:], techAsset.DataAssetsStored[i+1:])                      // Shift a[i+1:] left one index.
								techAsset.DataAssetsStored[len(techAsset.DataAssetsStored)-1] = ""                          // Erase last element (write zero value).
								techAsset.DataAssetsStored = techAsset.DataAssetsStored[:len(techAsset.DataAssetsStored)-1] // Truncate slice.
							}
						}
					}
					if techAsset.CommunicationLinks != nil {
						for title, commLink := range techAsset.CommunicationLinks {
							for i, dataAssetSent := range commLink.DataAssetsSent {
								referencedAsset := fmt.Sprintf("%v", dataAssetSent)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.CommunicationLinks[title].DataAssetsSent[i:], techAsset.CommunicationLinks[title].DataAssetsSent[i+1:]) // Shift a[i+1:] left one index.
									techAsset.CommunicationLinks[title].DataAssetsSent[len(techAsset.CommunicationLinks[title].DataAssetsSent)-1] = ""     // Erase last element (write zero value).
									x := techAsset.CommunicationLinks[title]
									x.DataAssetsSent = techAsset.CommunicationLinks[title].DataAssetsSent[:len(techAsset.CommunicationLinks[title].DataAssetsSent)-1] // Truncate slice.
									techAsset.CommunicationLinks[title] = x
								}
							}
							for i, dataAssetReceived := range commLink.DataAssetsReceived {
								referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.CommunicationLinks[title].DataAssetsReceived[i:], techAsset.CommunicationLinks[title].DataAssetsReceived[i+1:]) // Shift a[i+1:] left one index.
									techAsset.CommunicationLinks[title].DataAssetsReceived[len(techAsset.CommunicationLinks[title].DataAssetsReceived)-1] = ""     // Erase last element (write zero value).
									x := techAsset.CommunicationLinks[title]
									x.DataAssetsReceived = techAsset.CommunicationLinks[title].DataAssetsReceived[:len(techAsset.CommunicationLinks[title].DataAssetsReceived)-1] // Truncate slice.
									techAsset.CommunicationLinks[title] = x
								}
							}
						}
					}
				}
				for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
					if individualRiskCat.RisksIdentified != nil {
						for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
							if individualRiskInstance.MostRelevantDataAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
								x.MostRelevantDataAsset = "" // TODO needs more testing
								modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.DataAssets, title)
				ok = context.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Deletion")
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":            "data asset deleted",
						"id":                 dataAsset.ID,
						"references_deleted": referencesDeleted, // in order to signal to clients, that other model parts might've been deleted as well
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

type payloadSharedRuntime struct {
	Title                  string   `yaml:"title" json:"title"`
	Id                     string   `yaml:"id" json:"id"`
	Description            string   `yaml:"description" json:"description"`
	Tags                   []string `yaml:"tags" json:"tags"`
	TechnicalAssetsRunning []string `yaml:"technical_assets_running" json:"technical_assets_running"`
}

func (context *Context) setSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				payload := payloadSharedRuntime{}
				err := ginContext.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					ginContext.JSON(http.StatusBadRequest, gin.H{
						"error": "unable to parse request payload",
					})
					return
				}
				sharedRuntimeInput, ok := context.populateSharedRuntime(ginContext, payload)
				if !ok {
					return
				}
				// in order to also update the title, remove the shared runtime from the map and re-insert it (with new key)
				delete(modelInput.SharedRuntimes, title)
				modelInput.SharedRuntimes[payload.Title] = sharedRuntimeInput
				idChanged := sharedRuntimeInput.ID != sharedRuntime.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
						if individualRiskCat.RisksIdentified != nil {
							for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
								if individualRiskInstance.MostRelevantSharedRuntime == sharedRuntime.ID { // apply the ID change
									x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
									x.MostRelevantSharedRuntime = sharedRuntimeInput.ID // TODO needs more testing
									modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
								}
							}
						}
					}
				}
				ok = context.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Update")
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":    "shared runtime updated",
						"id":         sharedRuntimeInput.ID,
						"id_changed": idChanged, // in order to signal to clients, that other model parts might've received updates as well and should be reloaded
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

type payloadDataAsset struct {
	Title                  string   `yaml:"title" json:"title"`
	Id                     string   `yaml:"id" json:"id"`
	Description            string   `yaml:"description" json:"description"`
	Usage                  string   `yaml:"usage" json:"usage"`
	Tags                   []string `yaml:"tags" json:"tags"`
	Origin                 string   `yaml:"origin" json:"origin"`
	Owner                  string   `yaml:"owner" json:"owner"`
	Quantity               string   `yaml:"quantity" json:"quantity"`
	Confidentiality        string   `yaml:"confidentiality" json:"confidentiality"`
	Integrity              string   `yaml:"integrity" json:"integrity"`
	Availability           string   `yaml:"availability" json:"availability"`
	JustificationCiaRating string   `yaml:"justification_cia_rating" json:"justification_cia_rating"`
}

func (context *Context) setDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				payload := payloadDataAsset{}
				err := ginContext.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					ginContext.JSON(http.StatusBadRequest, gin.H{
						"error": "unable to parse request payload",
					})
					return
				}
				dataAssetInput, ok := context.populateDataAsset(ginContext, payload)
				if !ok {
					return
				}
				// in order to also update the title, remove the asset from the map and re-insert it (with new key)
				delete(modelInput.DataAssets, title)
				modelInput.DataAssets[payload.Title] = dataAssetInput
				idChanged := dataAssetInput.ID != dataAsset.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					// also update all usages to point to the new (changed) ID !!
					for techAssetTitle, techAsset := range modelInput.TechnicalAssets {
						if techAsset.DataAssetsProcessed != nil {
							for i, parsedChangeCandidateAsset := range techAsset.DataAssetsProcessed {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.TechnicalAssets[techAssetTitle].DataAssetsProcessed[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.DataAssetsStored != nil {
							for i, parsedChangeCandidateAsset := range techAsset.DataAssetsStored {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.TechnicalAssets[techAssetTitle].DataAssetsStored[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.CommunicationLinks != nil {
							for title, commLink := range techAsset.CommunicationLinks {
								for i, dataAssetSent := range commLink.DataAssetsSent {
									referencedAsset := fmt.Sprintf("%v", dataAssetSent)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.TechnicalAssets[techAssetTitle].CommunicationLinks[title].DataAssetsSent[i] = dataAssetInput.ID
									}
								}
								for i, dataAssetReceived := range commLink.DataAssetsReceived {
									referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.TechnicalAssets[techAssetTitle].CommunicationLinks[title].DataAssetsReceived[i] = dataAssetInput.ID
									}
								}
							}
						}
					}
					for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
						if individualRiskCat.RisksIdentified != nil {
							for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
								if individualRiskInstance.MostRelevantDataAsset == dataAsset.ID { // apply the ID change
									x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
									x.MostRelevantDataAsset = dataAssetInput.ID // TODO needs more testing
									modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
								}
							}
						}
					}
				}
				ok = context.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Update")
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":    "data asset updated",
						"id":         dataAssetInput.ID,
						"id_changed": idChanged, // in order to signal to clients, that other model parts might've received updates as well and should be reloaded
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func (context *Context) getSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				ginContext.JSON(http.StatusOK, gin.H{
					title: sharedRuntime,
				})
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func (context *Context) createNewSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSharedRuntime{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.SharedRuntimes[payload.Title]; exists {
			ginContext.JSON(http.StatusConflict, gin.H{
				"error": "shared runtime with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by its "id", so do this uniqueness check also
		for _, runtime := range modelInput.SharedRuntimes {
			if runtime.ID == payload.Id {
				ginContext.JSON(http.StatusConflict, gin.H{
					"error": "shared runtime with this id already exists",
				})
				return
			}
		}
		if !context.checkTechnicalAssetsExisting(modelInput, payload.TechnicalAssetsRunning) {
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "referenced technical asset does not exist",
			})
			return
		}
		sharedRuntimeInput, ok := context.populateSharedRuntime(ginContext, payload)
		if !ok {
			return
		}
		if modelInput.SharedRuntimes == nil {
			modelInput.SharedRuntimes = make(map[string]input.InputSharedRuntime)
		}
		modelInput.SharedRuntimes[payload.Title] = sharedRuntimeInput
		ok = context.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Creation")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "shared runtime created",
				"id":      sharedRuntimeInput.ID,
			})
		}
	}
}

func (context *Context) checkTechnicalAssetsExisting(modelInput input.ModelInput, techAssetIDs []string) (ok bool) {
	for _, techAssetID := range techAssetIDs {
		exists := false
		for _, val := range modelInput.TechnicalAssets {
			if val.ID == techAssetID {
				exists = true
				break
			}
		}
		if !exists {
			return false
		}
	}
	return true
}

func (context *Context) populateSharedRuntime(_ *gin.Context, payload payloadSharedRuntime) (sharedRuntimeInput input.InputSharedRuntime, ok bool) {
	sharedRuntimeInput = input.InputSharedRuntime{
		ID:                     payload.Id,
		Description:            payload.Description,
		Tags:                   lowerCaseAndTrim(payload.Tags),
		TechnicalAssetsRunning: payload.TechnicalAssetsRunning,
	}
	return sharedRuntimeInput, true
}

func (context *Context) deleteSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		referencesDeleted := false
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				// also remove all usages of this shared runtime !!
				for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
					if individualRiskCat.RisksIdentified != nil {
						for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
							if individualRiskInstance.MostRelevantSharedRuntime == sharedRuntime.ID { // apply the removal
								referencesDeleted = true
								x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
								x.MostRelevantSharedRuntime = "" // TODO needs more testing
								modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.SharedRuntimes, title)
				ok = context.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Deletion")
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":            "shared runtime deleted",
						"id":                 sharedRuntime.ID,
						"references_deleted": referencesDeleted, // in order to signal to clients, that other model parts might've been deleted as well
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func (context *Context) createNewDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadDataAsset{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.DataAssets[payload.Title]; exists {
			ginContext.JSON(http.StatusConflict, gin.H{
				"error": "data asset with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by its "id", so do this uniqueness check also
		for _, asset := range modelInput.DataAssets {
			if asset.ID == payload.Id {
				ginContext.JSON(http.StatusConflict, gin.H{
					"error": "data asset with this id already exists",
				})
				return
			}
		}
		dataAssetInput, ok := context.populateDataAsset(ginContext, payload)
		if !ok {
			return
		}
		if modelInput.DataAssets == nil {
			modelInput.DataAssets = make(map[string]input.InputDataAsset)
		}
		modelInput.DataAssets[payload.Title] = dataAssetInput
		ok = context.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Creation")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "data asset created",
				"id":      dataAssetInput.ID,
			})
		}
	}
}

func (context *Context) populateDataAsset(ginContext *gin.Context, payload payloadDataAsset) (dataAssetInput input.InputDataAsset, ok bool) {
	usage, err := types.ParseUsage(payload.Usage)
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	quantity, err := types.ParseQuantity(payload.Quantity)
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	confidentiality, err := types.ParseConfidentiality(payload.Confidentiality)
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	integrity, err := types.ParseCriticality(payload.Integrity)
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	availability, err := types.ParseCriticality(payload.Availability)
	if err != nil {
		context.handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	dataAssetInput = input.InputDataAsset{
		ID:                     payload.Id,
		Description:            payload.Description,
		Usage:                  usage.String(),
		Tags:                   lowerCaseAndTrim(payload.Tags),
		Origin:                 payload.Origin,
		Owner:                  payload.Owner,
		Quantity:               quantity.String(),
		Confidentiality:        confidentiality.String(),
		Integrity:              integrity.String(),
		Availability:           availability.String(),
		JustificationCiaRating: payload.JustificationCiaRating,
	}
	return dataAssetInput, true
}

func (context *Context) getDataAssets(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	aModel, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.DataAssets)
	}
}

func (context *Context) getTrustBoundaries(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	aModel, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.TrustBoundaries)
	}
}

func (context *Context) getSharedRuntimes(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	aModel, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.SharedRuntimes)
	}
}

func (context *Context) arrayOfStringValues(values []types.TypeEnum) []string {
	result := make([]string, 0)
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}

func (context *Context) getModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	_, yamlText, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		tmpResultFile, err := os.CreateTemp(*context.tempFolder, "threagile-*.yaml")
		checkErr(err)
		err = os.WriteFile(tmpResultFile.Name(), []byte(yamlText), 0400)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to stream model file",
			})
			return
		}
		defer func() { _ = os.Remove(tmpResultFile.Name()) }()
		ginContext.FileAttachment(tmpResultFile.Name(), context.inputFile)
	}
}

type payloadSecurityRequirements map[string]string

func (context *Context) setSecurityRequirements(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSecurityRequirements{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.SecurityRequirements = payload
		ok = context.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Security Requirements Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (context *Context) getSecurityRequirements(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	aModel, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.SecurityRequirements)
	}
}

type payloadAbuseCases map[string]string

func (context *Context) setAbuseCases(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadAbuseCases{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.AbuseCases = payload
		ok = context.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Abuse Cases Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (context *Context) getAbuseCases(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	aModel, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.AbuseCases)
	}
}

type payloadOverview struct {
	ManagementSummaryComment string         `yaml:"management_summary_comment" json:"management_summary_comment"`
	BusinessCriticality      string         `yaml:"business_criticality" json:"business_criticality"`
	BusinessOverview         input.Overview `yaml:"business_overview" json:"business_overview"`
	TechnicalOverview        input.Overview `yaml:"technical_overview" json:"technical_overview"`
}

func (context *Context) setOverview(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadOverview{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		criticality, err := types.ParseCriticality(payload.BusinessCriticality)
		if err != nil {
			context.handleErrorInServiceCall(err, ginContext)
			return
		}
		modelInput.ManagementSummaryComment = payload.ManagementSummaryComment
		modelInput.BusinessCriticality = criticality.String()
		modelInput.BusinessOverview.Description = payload.BusinessOverview.Description
		modelInput.BusinessOverview.Images = payload.BusinessOverview.Images
		modelInput.TechnicalOverview.Description = payload.TechnicalOverview.Description
		modelInput.TechnicalOverview.Images = payload.TechnicalOverview.Images
		ok = context.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Overview Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (context *Context) handleErrorInServiceCall(err error, ginContext *gin.Context) {
	log.Println(err)
	ginContext.JSON(http.StatusBadRequest, gin.H{
		"error": strings.TrimSpace(err.Error()),
	})
}

func (context *Context) getOverview(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	aModel, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, gin.H{
			"management_summary_comment": aModel.ManagementSummaryComment,
			"business_criticality":       aModel.BusinessCriticality,
			"business_overview":          aModel.BusinessOverview,
			"technical_overview":         aModel.TechnicalOverview,
		})
	}
}

type payloadCover struct {
	Title  string       `yaml:"title" json:"title"`
	Date   time.Time    `yaml:"date" json:"date"`
	Author input.Author `yaml:"author" json:"author"`
}

func (context *Context) setCover(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	modelInput, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadCover{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.Title = payload.Title
		if !payload.Date.IsZero() {
			modelInput.Date = payload.Date.Format("2006-01-02")
		}
		modelInput.Author.Name = payload.Author.Name
		modelInput.Author.Homepage = payload.Author.Homepage
		ok = context.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Cover Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (context *Context) getCover(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	aModel, _, ok := context.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, gin.H{
			"title":  aModel.Title,
			"date":   aModel.Date,
			"author": aModel.Author,
		})
	}
}

// creates a sub-folder (named by a new UUID) inside the token folder
func (context *Context) createNewModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	ok = context.checkObjectCreationThrottler(ginContext, "MODEL")
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)

	aUuid := uuid.New().String()
	err := os.Mkdir(context.folderNameForModel(folderNameOfKey, aUuid), 0700)
	if err != nil {
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create model",
		})
		return
	}

	aYaml := `title: New Threat Model
threagile_version: ` + docs.ThreagileVersion + `
author:
  name: ""
  homepage: ""
date:
business_overview:
  description: ""
  images: []
technical_overview:
  description: ""
  images: []
business_criticality: ""
management_summary_comment: ""
questions: {}
abuse_cases: {}
security_requirements: {}
tags_available: []
data_assets: {}
technical_assets: {}
trust_boundaries: {}
shared_runtimes: {}
individual_risk_categories: {}
risk_tracking: {}
diagram_tweak_nodesep: ""
diagram_tweak_ranksep: ""
diagram_tweak_edge_layout: ""
diagram_tweak_suppress_edge_labels: false
diagram_tweak_invisible_connections_between_assets: []
diagram_tweak_same_rank_assets: []`

	ok = context.writeModelYAML(ginContext, aYaml, key, context.folderNameForModel(folderNameOfKey, aUuid), "New Model Creation", true)
	if ok {
		ginContext.JSON(http.StatusCreated, gin.H{
			"message": "model created",
			"id":      aUuid,
		})
	}
}

type payloadModels struct {
	ID                string    `yaml:"id" json:"id"`
	Title             string    `yaml:"title" json:"title"`
	TimestampCreated  time.Time `yaml:"timestamp_created" json:"timestamp_created"`
	TimestampModified time.Time `yaml:"timestamp_modified" json:"timestamp_modified"`
}

func (context *Context) listModels(ginContext *gin.Context) { // TODO currently returns error when any model is no longer valid in syntax, so eventually have some fallback to not just bark on an invalid model...
	folderNameOfKey, key, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)

	result := make([]payloadModels, 0)
	modelFolders, err := os.ReadDir(folderNameOfKey)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	for _, dirEntry := range modelFolders {
		if dirEntry.IsDir() {
			modelStat, err := os.Stat(filepath.Join(folderNameOfKey, dirEntry.Name(), context.inputFile))
			if err != nil {
				log.Println(err)
				ginContext.JSON(http.StatusNotFound, gin.H{
					"error": "unable to list model",
				})
				return
			}
			aModel, _, ok := context.readModel(ginContext, dirEntry.Name(), key, folderNameOfKey)
			if !ok {
				return
			}
			fileInfo, err := dirEntry.Info()
			if err != nil {
				log.Println(err)
				ginContext.JSON(http.StatusNotFound, gin.H{
					"error": "unable to get file info",
				})
				return
			}
			result = append(result, payloadModels{
				ID:                dirEntry.Name(),
				Title:             aModel.Title,
				TimestampCreated:  fileInfo.ModTime(),
				TimestampModified: modelStat.ModTime(),
			})
		}
	}
	ginContext.JSON(http.StatusOK, result)
}

func (context *Context) deleteModel(ginContext *gin.Context) {
	folderNameOfKey, _, ok := context.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	context.lockFolder(folderNameOfKey)
	defer context.unlockFolder(folderNameOfKey)
	folder, ok := context.checkModelFolder(ginContext, ginContext.Param("model-id"), folderNameOfKey)
	if ok {
		err := os.RemoveAll(folder)
		if err != nil {
			ginContext.JSON(http.StatusNotFound, gin.H{
				"error": "model not found",
			})
		}
		ginContext.JSON(http.StatusOK, gin.H{
			"message": "model deleted",
		})
	}
}

func (context *Context) checkModelFolder(ginContext *gin.Context, modelUUID string, folderNameOfKey string) (modelFolder string, ok bool) {
	uuidParsed, err := uuid.Parse(modelUUID)
	if err != nil {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	modelFolder = context.folderNameForModel(folderNameOfKey, uuidParsed.String())
	if _, err := os.Stat(modelFolder); os.IsNotExist(err) {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	return modelFolder, true
}

func (context *Context) readModel(ginContext *gin.Context, modelUUID string, key []byte, folderNameOfKey string) (modelInputResult input.ModelInput, yamlText string, ok bool) {
	modelFolder, ok := context.checkModelFolder(ginContext, modelUUID, folderNameOfKey)
	if !ok {
		return modelInputResult, yamlText, false
	}
	cryptoKey := context.generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	fileBytes, err := os.ReadFile(filepath.Join(modelFolder, context.inputFile))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	nonce := fileBytes[0:12]
	ciphertext := fileBytes[12:]
	plaintext, err := aesGcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	r, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r)
	modelInput := new(input.ModelInput).Defaults()
	yamlBytes := buf.Bytes()
	err = yaml.Unmarshal(yamlBytes, &modelInput)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	return *modelInput, string(yamlBytes), true
}

func (context *Context) writeModel(ginContext *gin.Context, key []byte, folderNameOfKey string, modelInput *input.ModelInput, changeReasonForHistory string) (ok bool) {
	modelFolder, ok := context.checkModelFolder(ginContext, ginContext.Param("model-id"), folderNameOfKey)
	if ok {
		modelInput.ThreagileVersion = docs.ThreagileVersion
		yamlBytes, err := yaml.Marshal(modelInput)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
		/*
			yamlBytes = model.ReformatYAML(yamlBytes)
		*/
		return context.writeModelYAML(ginContext, string(yamlBytes), key, modelFolder, changeReasonForHistory, false)
	}
	return false
}

func (context *Context) writeModelYAML(ginContext *gin.Context, yaml string, key []byte, modelFolder string, changeReasonForHistory string, skipBackup bool) (ok bool) {
	if *context.verbose {
		fmt.Println("about to write " + strconv.Itoa(len(yaml)) + " bytes of yaml into model folder: " + modelFolder)
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(yaml))
	_ = w.Close()
	plaintext := b.Bytes()
	cryptoKey := context.generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	ciphertext := aesGcm.Seal(nil, nonce, plaintext, nil)
	if !skipBackup {
		err = context.backupModelToHistory(modelFolder, changeReasonForHistory)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
	}
	f, err := os.Create(filepath.Join(modelFolder, context.inputFile))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	_, _ = f.Write(nonce)
	_, _ = f.Write(ciphertext)
	_ = f.Close()
	return true
}

func (context *Context) backupModelToHistory(modelFolder string, changeReasonForHistory string) (err error) {
	historyFolder := filepath.Join(modelFolder, "history")
	if _, err := os.Stat(historyFolder); os.IsNotExist(err) {
		err = os.Mkdir(historyFolder, 0700)
		if err != nil {
			return err
		}
	}
	input, err := os.ReadFile(filepath.Join(modelFolder, context.inputFile))
	if err != nil {
		return err
	}
	historyFile := filepath.Join(historyFolder, time.Now().Format("2006-01-02 15:04:05")+" "+changeReasonForHistory+".backup")
	err = os.WriteFile(historyFile, input, 0400)
	if err != nil {
		return err
	}
	// now delete any old files if over limit to keep
	files, err := os.ReadDir(historyFolder)
	if err != nil {
		return err
	}
	if len(files) > context.backupHistoryFilesToKeep {
		requiredToDelete := len(files) - context.backupHistoryFilesToKeep
		sort.Slice(files, func(i, j int) bool {
			return files[i].Name() < files[j].Name()
		})
		for _, file := range files {
			requiredToDelete--
			err = os.Remove(filepath.Join(historyFolder, file.Name()))
			if err != nil {
				return err
			}
			if requiredToDelete <= 0 {
				break
			}
		}
	}
	return
}

func (context *Context) generateKeyFromAlreadyStrongRandomInput(alreadyRandomInput []byte) []byte {
	// Establish the parameters to use for Argon2.
	p := &argon2Params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   keySize,
	}
	// As the input is already cryptographically secure random, the salt is simply the first n bytes
	salt := alreadyRandomInput[0:p.saltLength]
	hash := argon2.IDKey(alreadyRandomInput[p.saltLength:], salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	return hash
}

func (context *Context) folderNameForModel(folderNameOfKey string, uuid string) string {
	return filepath.Join(folderNameOfKey, uuid)
}

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var throttlerLock sync.Mutex

var createdObjectsThrottler = make(map[string][]int64)

func (context *Context) checkObjectCreationThrottler(ginContext *gin.Context, typeName string) bool {
	throttlerLock.Lock()
	defer throttlerLock.Unlock()

	// remove all elements older than 3 minutes (= 180000000000 ns)
	now := time.Now().UnixNano()
	cutoff := now - 180000000000
	for keyCheck := range createdObjectsThrottler {
		for i := 0; i < len(createdObjectsThrottler[keyCheck]); i++ {
			if createdObjectsThrottler[keyCheck][i] < cutoff {
				// Remove the element at index i from slice (safe while looping using i as iterator)
				createdObjectsThrottler[keyCheck] = append(createdObjectsThrottler[keyCheck][:i], createdObjectsThrottler[keyCheck][i+1:]...)
				i-- // Since we just deleted a[i], we must redo that index
			}
		}
		length := len(createdObjectsThrottler[keyCheck])
		if length == 0 {
			delete(createdObjectsThrottler, keyCheck)
		}
		/*
			if *verbose {
				log.Println("Throttling count: "+strconv.Itoa(length))
			}
		*/
	}

	// check current request
	keyHash := hash(typeName) // getting the real client ip is not easy inside fully encapsulated containerized runtime
	if _, ok := createdObjectsThrottler[keyHash]; !ok {
		createdObjectsThrottler[keyHash] = make([]int64, 0)
	}
	// check the limit of 20 creations for this type per 3 minutes
	withinLimit := len(createdObjectsThrottler[keyHash]) < 20
	if withinLimit {
		createdObjectsThrottler[keyHash] = append(createdObjectsThrottler[keyHash], now)
		return true
	}
	ginContext.JSON(http.StatusTooManyRequests, gin.H{
		"error": "object creation throttling exceeded (denial-of-service protection): please wait some time and try again",
	})
	return false
}

var locksByFolderName = make(map[string]*sync.Mutex)

func (context *Context) lockFolder(folderName string) {
	context.globalLock.Lock()
	defer context.globalLock.Unlock()
	_, exists := locksByFolderName[folderName]
	if !exists {
		locksByFolderName[folderName] = &sync.Mutex{}
	}
	locksByFolderName[folderName].Lock()
}

func (context *Context) unlockFolder(folderName string) {
	if _, exists := locksByFolderName[folderName]; exists {
		locksByFolderName[folderName].Unlock()
		delete(locksByFolderName, folderName)
	}
}

func (context *Context) folderNameFromKey(key []byte) string {
	sha512Hash := hashSHA256(key)
	return filepath.Join(*context.serverFolder, context.keyDir, sha512Hash)
}

func hashSHA256(key []byte) string {
	hasher := sha512.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (context *Context) createKey(ginContext *gin.Context) {
	ok := context.checkObjectCreationThrottler(ginContext, "KEY")
	if !ok {
		return
	}
	context.globalLock.Lock()
	defer context.globalLock.Unlock()

	keyBytesArr := make([]byte, keySize)
	n, err := rand.Read(keyBytesArr[:])
	if n != keySize || err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create key",
		})
		return
	}
	err = os.MkdirAll(context.folderNameFromKey(keyBytesArr), 0700)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create key",
		})
		return
	}
	ginContext.JSON(http.StatusCreated, gin.H{
		"key": base64.RawURLEncoding.EncodeToString(keyBytesArr[:]),
	})
}

func (context *Context) checkTokenToFolderName(ginContext *gin.Context) (folderNameOfKey string, key []byte, ok bool) {
	header := tokenHeader{}
	if err := ginContext.ShouldBindHeader(&header); err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Token))
	if len(token) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
	context.globalLock.Lock()
	defer context.globalLock.Unlock()
	housekeepingTokenMaps() // to remove timed-out ones
	tokenHash := hashSHA256(token)
	if timeoutStruct, exists := mapTokenHashToTimeoutStruct[tokenHash]; exists {
		// re-create the key from token
		key := xor(token, timeoutStruct.xorRand)
		folderNameOfKey := context.folderNameFromKey(key)
		if _, err := os.Stat(folderNameOfKey); os.IsNotExist(err) {
			log.Println(err)
			ginContext.JSON(http.StatusNotFound, gin.H{
				"error": "token not found",
			})
			return folderNameOfKey, key, false
		}
		timeoutStruct.lastAccessedNanoTime = time.Now().UnixNano()
		return folderNameOfKey, key, true
	} else {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
}

func xor(key []byte, xor []byte) []byte {
	if len(key) != len(xor) {
		panic(errors.New("key length not matching XOR length"))
	}
	result := make([]byte, len(xor))
	for i, b := range key {
		result[i] = b ^ xor[i]
	}
	return result
}

type timeoutStruct struct {
	xorRand                               []byte
	createdNanoTime, lastAccessedNanoTime int64
}

var mapTokenHashToTimeoutStruct = make(map[string]timeoutStruct)

const extremeShortTimeoutsForTesting = false

func housekeepingTokenMaps() {
	now := time.Now().UnixNano()
	for tokenHash, val := range mapTokenHashToTimeoutStruct {
		if extremeShortTimeoutsForTesting {
			// remove all elements older than 1 minute (= 60000000000 ns) soft
			// and all elements older than 3 minutes (= 180000000000 ns) hard
			if now-val.lastAccessedNanoTime > 60000000000 || now-val.createdNanoTime > 180000000000 {
				fmt.Println("About to remove a token hash from maps")
				deleteTokenHashFromMaps(tokenHash)
			}
		} else {
			// remove all elements older than 30 minutes (= 1800000000000 ns) soft
			// and all elements older than 10 hours (= 36000000000000 ns) hard
			if now-val.lastAccessedNanoTime > 1800000000000 || now-val.createdNanoTime > 36000000000000 {
				deleteTokenHashFromMaps(tokenHash)
			}
		}
	}
}

func deleteTokenHashFromMaps(tokenHash string) {
	delete(mapTokenHashToTimeoutStruct, tokenHash)
	for folderName, check := range mapFolderNameToTokenHash {
		if check == tokenHash {
			delete(mapFolderNameToTokenHash, folderName)
			break
		}
	}
}

type keyHeader struct {
	Key string `header:"key"`
}

func (context *Context) checkKeyToFolderName(ginContext *gin.Context) (folderNameOfKey string, key []byte, ok bool) {
	header := keyHeader{}
	if err := ginContext.ShouldBindHeader(&header); err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Key))
	if len(key) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	folderNameOfKey = context.folderNameFromKey(key)
	if _, err := os.Stat(folderNameOfKey); os.IsNotExist(err) {
		log.Println(err)
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	return folderNameOfKey, key, true
}

func (context *Context) deleteKey(ginContext *gin.Context) {
	folderName, _, ok := context.checkKeyToFolderName(ginContext)
	if !ok {
		return
	}
	context.globalLock.Lock()
	defer context.globalLock.Unlock()
	err := os.RemoveAll(folderName)
	if err != nil {
		log.Println("error during key delete: " + err.Error())
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return
	}
	ginContext.JSON(http.StatusOK, gin.H{
		"message": "key deleted",
	})
}

func (context *Context) ParseCommandlineArgs() {
	context.tempFolder = flag.String("temp-dir", context.tempDir, "temporary folder location")
	context.binFolder = flag.String("bin-dir", context.binDir, "binary folder location")
	context.appFolder = flag.String("app-dir", context.appDir, "app folder (default: "+context.appDir+")")
	context.serverFolder = flag.String("server-dir", context.dataDir, "base folder for server mode (default: "+context.dataDir+")")
	context.modelFilename = flag.String("model", context.inputFile, "input model yaml file")
	context.outputDir = flag.String("output", ".", "output directory")
	context.raaPlugin = flag.String("raa-run", "raa.so", "RAA calculation run (.so shared object) file name")
	context.executeModelMacro = flag.String("execute-model-macro", "", "Execute model macro (by ID)")
	context.testParseModel = flag.Bool("test-parse-model", false, "test parse model functionality")
	context.createExampleModel = flag.Bool("create-example-model", false, "just create an example model named threagile-example-model.yaml in the output directory")
	context.createStubModel = flag.Bool("create-stub-model", false, "just create a minimal stub model named threagile-stub-model.yaml in the output directory")
	context.createEditingSupport = flag.Bool("create-editing-support", false, "just create some editing support stuff in the output directory")
	context.serverPort = flag.Int("server", 0, "start a server (instead of commandline execution) on the given port")
	context.templateFilename = flag.String("background", "background.pdf", "background pdf file")
	context.generateDataFlowDiagram = flag.Bool("generate-data-flow-diagram", true, "generate data-flow diagram")
	context.generateDataAssetDiagram = flag.Bool("generate-data-asset-diagram", true, "generate data asset diagram")
	context.generateRisksJSON = flag.Bool("generate-risks-json", true, "generate risks json")
	context.generateTechnicalAssetsJSON = flag.Bool("generate-technical-assets-json", true, "generate technical assets json")
	context.generateStatsJSON = flag.Bool("generate-stats-json", true, "generate stats json")
	context.generateRisksExcel = flag.Bool("generate-risks-excel", true, "generate risks excel")
	context.generateTagsExcel = flag.Bool("generate-tags-excel", true, "generate tags excel")
	context.generateReportPDF = flag.Bool("generate-report-pdf", true, "generate report pdf, including diagrams")
	context.diagramDPI = flag.Int("diagram-dpi", context.defaultGraphvizDPI, "DPI used to render: maximum is "+strconv.Itoa(context.maxGraphvizDPI)+"")
	context.skipRiskRules = flag.String("skip-risk-rules", "", "comma-separated list of risk rules (by their ID) to skip")
	context.riskRulesPlugins = flag.String("custom-risk-rules-plugins", "", "comma-separated list of plugins (.so shared object) file names with custom risk rules to load")
	context.verbose = flag.Bool("verbose", false, "verbose output")
	context.ignoreOrphanedRiskTracking = flag.Bool("ignore-orphaned-risk-tracking", false, "ignore orphaned risk tracking (just log them) not matching a concrete risk")
	listRiskRules := flag.Bool("list-risk-rules", false, "print risk rules")
	explainTypes := flag.Bool("explain-types", false, "Detailed explanation of all the types")
	explainRiskRules := flag.Bool("explain-risk-rules", false, "Detailed explanation of all the risk rules")
	explainModelMacros := flag.Bool("explain-model-macros", false, "Detailed explanation of all the model macros")
	print3rdParty := flag.Bool("print-3rd-party-licenses", false, "print 3rd-party license information")
	license := flag.Bool("print-license", false, "print license information")
	flag.Parse()
	if *context.diagramDPI < 20 {
		*context.diagramDPI = 20
	} else if *context.diagramDPI > context.maxGraphvizDPI {
		*context.diagramDPI = 300
	}
	if *listRiskRules {
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
		fmt.Println("The following risk rules are available (can be extended via custom risk rules):")
		fmt.Println()
		fmt.Println("------------------")
		fmt.Println("Custom risk rules:")
		fmt.Println("------------------")
		context.loadCustomRiskRules()
		for id, customRule := range context.customRiskRules {
			fmt.Println(id, "-->", customRule.Category.Title, "--> with tags:", customRule.Tags)
		}
		fmt.Println()
		fmt.Println("--------------------")
		fmt.Println("Built-in risk rules:")
		fmt.Println("--------------------")
		fmt.Println(accidentalsecretleak.Category().Id, "-->", accidentalsecretleak.Category().Title, "--> with tags:", accidentalsecretleak.SupportedTags())
		fmt.Println(codebackdooring.Category().Id, "-->", codebackdooring.Category().Title, "--> with tags:", codebackdooring.SupportedTags())
		fmt.Println(containerbaseimagebackdooring.Category().Id, "-->", containerbaseimagebackdooring.Category().Title, "--> with tags:", containerbaseimagebackdooring.SupportedTags())
		fmt.Println(containerplatformescape.Category().Id, "-->", containerplatformescape.Category().Title, "--> with tags:", containerplatformescape.SupportedTags())
		fmt.Println(crosssiterequestforgery.Category().Id, "-->", crosssiterequestforgery.Category().Title, "--> with tags:", crosssiterequestforgery.SupportedTags())
		fmt.Println(crosssitescripting.Category().Id, "-->", crosssitescripting.Category().Title, "--> with tags:", crosssitescripting.SupportedTags())
		fmt.Println(dosriskyaccessacrosstrustboundary.Category().Id, "-->", dosriskyaccessacrosstrustboundary.Category().Title, "--> with tags:", dosriskyaccessacrosstrustboundary.SupportedTags())
		fmt.Println(incompletemodel.Category().Id, "-->", incompletemodel.Category().Title, "--> with tags:", incompletemodel.SupportedTags())
		fmt.Println(ldapinjection.Category().Id, "-->", ldapinjection.Category().Title, "--> with tags:", ldapinjection.SupportedTags())
		fmt.Println(missingauthentication.Category().Id, "-->", missingauthentication.Category().Title, "--> with tags:", missingauthentication.SupportedTags())
		fmt.Println(missingauthenticationsecondfactor.Category().Id, "-->", missingauthenticationsecondfactor.Category().Title, "--> with tags:", missingauthenticationsecondfactor.SupportedTags())
		fmt.Println(missingbuildinfrastructure.Category().Id, "-->", missingbuildinfrastructure.Category().Title, "--> with tags:", missingbuildinfrastructure.SupportedTags())
		fmt.Println(missingcloudhardening.Category().Id, "-->", missingcloudhardening.Category().Title, "--> with tags:", missingcloudhardening.SupportedTags())
		fmt.Println(missingfilevalidation.Category().Id, "-->", missingfilevalidation.Category().Title, "--> with tags:", missingfilevalidation.SupportedTags())
		fmt.Println(missinghardening.Category().Id, "-->", missinghardening.Category().Title, "--> with tags:", missinghardening.SupportedTags())
		fmt.Println(missingidentitypropagation.Category().Id, "-->", missingidentitypropagation.Category().Title, "--> with tags:", missingidentitypropagation.SupportedTags())
		fmt.Println(missingidentityproviderisolation.Category().Id, "-->", missingidentityproviderisolation.Category().Title, "--> with tags:", missingidentityproviderisolation.SupportedTags())
		fmt.Println(missingidentitystore.Category().Id, "-->", missingidentitystore.Category().Title, "--> with tags:", missingidentitystore.SupportedTags())
		fmt.Println(missingnetworksegmentation.Category().Id, "-->", missingnetworksegmentation.Category().Title, "--> with tags:", missingnetworksegmentation.SupportedTags())
		fmt.Println(missingvault.Category().Id, "-->", missingvault.Category().Title, "--> with tags:", missingvault.SupportedTags())
		fmt.Println(missingvaultisolation.Category().Id, "-->", missingvaultisolation.Category().Title, "--> with tags:", missingvaultisolation.SupportedTags())
		fmt.Println(missingwaf.Category().Id, "-->", missingwaf.Category().Title, "--> with tags:", missingwaf.SupportedTags())
		fmt.Println(mixedtargetsonsharedruntime.Category().Id, "-->", mixedtargetsonsharedruntime.Category().Title, "--> with tags:", mixedtargetsonsharedruntime.SupportedTags())
		fmt.Println(pathtraversal.Category().Id, "-->", pathtraversal.Category().Title, "--> with tags:", pathtraversal.SupportedTags())
		fmt.Println(pushinsteadofpulldeployment.Category().Id, "-->", pushinsteadofpulldeployment.Category().Title, "--> with tags:", pushinsteadofpulldeployment.SupportedTags())
		fmt.Println(searchqueryinjection.Category().Id, "-->", searchqueryinjection.Category().Title, "--> with tags:", searchqueryinjection.SupportedTags())
		fmt.Println(serversiderequestforgery.Category().Id, "-->", serversiderequestforgery.Category().Title, "--> with tags:", serversiderequestforgery.SupportedTags())
		fmt.Println(serviceregistrypoisoning.Category().Id, "-->", serviceregistrypoisoning.Category().Title, "--> with tags:", serviceregistrypoisoning.SupportedTags())
		fmt.Println(sqlnosqlinjection.Category().Id, "-->", sqlnosqlinjection.Category().Title, "--> with tags:", sqlnosqlinjection.SupportedTags())
		fmt.Println(uncheckeddeployment.Category().Id, "-->", uncheckeddeployment.Category().Title, "--> with tags:", uncheckeddeployment.SupportedTags())
		fmt.Println(unencryptedasset.Category().Id, "-->", unencryptedasset.Category().Title, "--> with tags:", unencryptedasset.SupportedTags())
		fmt.Println(unencryptedcommunication.Category().Id, "-->", unencryptedcommunication.Category().Title, "--> with tags:", unencryptedcommunication.SupportedTags())
		fmt.Println(unguardedaccessfrominternet.Category().Id, "-->", unguardedaccessfrominternet.Category().Title, "--> with tags:", unguardedaccessfrominternet.SupportedTags())
		fmt.Println(unguardeddirectdatastoreaccess.Category().Id, "-->", unguardeddirectdatastoreaccess.Category().Title, "--> with tags:", unguardeddirectdatastoreaccess.SupportedTags())
		fmt.Println(unnecessarycommunicationlink.Category().Id, "-->", unnecessarycommunicationlink.Category().Title, "--> with tags:", unnecessarycommunicationlink.SupportedTags())
		fmt.Println(unnecessarydataasset.Category().Id, "-->", unnecessarydataasset.Category().Title, "--> with tags:", unnecessarydataasset.SupportedTags())
		fmt.Println(unnecessarydatatransfer.Category().Id, "-->", unnecessarydatatransfer.Category().Title, "--> with tags:", unnecessarydatatransfer.SupportedTags())
		fmt.Println(unnecessarytechnicalasset.Category().Id, "-->", unnecessarytechnicalasset.Category().Title, "--> with tags:", unnecessarytechnicalasset.SupportedTags())
		fmt.Println(untrusteddeserialization.Category().Id, "-->", untrusteddeserialization.Category().Title, "--> with tags:", untrusteddeserialization.SupportedTags())
		fmt.Println(wrongcommunicationlinkcontent.Category().Id, "-->", wrongcommunicationlinkcontent.Category().Title, "--> with tags:", wrongcommunicationlinkcontent.SupportedTags())
		fmt.Println(wrongtrustboundarycontent.Category().Id, "-->", wrongtrustboundarycontent.Category().Title, "--> with tags:", wrongtrustboundarycontent.SupportedTags())
		fmt.Println(xmlexternalentity.Category().Id, "-->", xmlexternalentity.Category().Title, "--> with tags:", xmlexternalentity.SupportedTags())
		fmt.Println()
		os.Exit(0)
	}
	if *explainTypes {
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
		fmt.Println("Explanation for the types:")
		fmt.Println()
		printExplainTypes("Authentication", types.AuthenticationValues())
		printExplainTypes("Authorization", types.AuthorizationValues())
		printExplainTypes("Confidentiality", types.ConfidentialityValues())
		printExplainTypes("Criticality", types.CriticalityValues())
		printExplainTypes("Data Breach Probability", types.DataBreachProbabilityValues())
		printExplainTypes("Data Format", types.DataFormatValues())
		printExplainTypes("Encryption", types.EncryptionStyleValues())
		printExplainTypes("Protocol", types.ProtocolValues())
		printExplainTypes("Quantity", types.QuantityValues())
		printExplainTypes("Risk Exploitation Impact", types.RiskExploitationImpactValues())
		printExplainTypes("Risk Exploitation likelihood", types.RiskExploitationLikelihoodValues())
		printExplainTypes("Risk Function", types.RiskFunctionValues())
		printExplainTypes("Risk Severity", types.RiskSeverityValues())
		printExplainTypes("Risk Status", types.RiskStatusValues())
		printExplainTypes("STRIDE", types.STRIDEValues())
		printExplainTypes("Technical Asset Machine", types.TechnicalAssetMachineValues())
		printExplainTypes("Technical Asset Size", types.TechnicalAssetSizeValues())
		printExplainTypes("Technical Asset Technology", types.TechnicalAssetTechnologyValues())
		printExplainTypes("Technical Asset Type", types.TechnicalAssetTypeValues())
		printExplainTypes("Trust Boundary Type", types.TrustBoundaryTypeValues())
		printExplainTypes("Usage", types.UsageValues())

		os.Exit(0)
	}
	if *explainModelMacros {
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
		fmt.Println("Explanation for the model macros:")
		fmt.Println()
		fmt.Printf("%v: %v\n", addbuildpipeline.GetMacroDetails().ID, addbuildpipeline.GetMacroDetails().Description)
		fmt.Printf("%v: %v\n", addvault.GetMacroDetails().ID, addvault.GetMacroDetails().Description)
		fmt.Printf("%v: %v\n", prettyprint.GetMacroDetails().ID, prettyprint.GetMacroDetails().Description)
		fmt.Printf("%v: %v\n", removeunusedtags.GetMacroDetails().ID, removeunusedtags.GetMacroDetails().Description)
		fmt.Printf("%v: %v\n", seedrisktracking.GetMacroDetails().ID, seedrisktracking.GetMacroDetails().Description)
		fmt.Printf("%v: %v\n", seedtags.GetMacroDetails().ID, seedtags.GetMacroDetails().Description)
		fmt.Println()
		os.Exit(0)

	}
	if *explainRiskRules {
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
		fmt.Println("Explanation for risk rules:")
		fmt.Println()
		fmt.Printf("%v: %v\n", accidentalsecretleak.Category().Id, accidentalsecretleak.Category().Description)
		fmt.Printf("%v: %v\n", codebackdooring.Category().Id, codebackdooring.Category().Description)
		fmt.Printf("%v: %v\n", containerbaseimagebackdooring.Category().Id, containerbaseimagebackdooring.Category().Description)
		fmt.Printf("%v: %v\n", containerplatformescape.Category().Id, containerplatformescape.Category().Description)
		fmt.Printf("%v: %v\n", crosssiterequestforgery.Category().Id, crosssiterequestforgery.Category().Description)
		fmt.Printf("%v: %v\n", crosssitescripting.Category().Id, crosssitescripting.Category().Description)
		fmt.Printf("%v: %v\n", dosriskyaccessacrosstrustboundary.Category().Id, dosriskyaccessacrosstrustboundary.Category().Description)
		fmt.Printf("%v: %v\n", incompletemodel.Category().Id, incompletemodel.Category().Description)
		fmt.Printf("%v: %v\n", ldapinjection.Category().Id, ldapinjection.Category().Description)
		fmt.Printf("%v: %v\n", missingauthentication.Category().Id, missingauthentication.Category().Description)
		fmt.Printf("%v: %v\n", missingauthenticationsecondfactor.Category().Id, missingauthenticationsecondfactor.Category().Description)
		fmt.Printf("%v: %v\n", missingbuildinfrastructure.Category().Id, missingbuildinfrastructure.Category().Description)
		fmt.Printf("%v: %v\n", missingcloudhardening.Category().Id, missingcloudhardening.Category().Description)
		fmt.Printf("%v: %v\n", missingfilevalidation.Category().Id, missingfilevalidation.Category().Description)
		fmt.Printf("%v: %v\n", missinghardening.Category().Id, missinghardening.Category().Description)
		fmt.Printf("%v: %v\n", missingidentitypropagation.Category().Id, missingidentitypropagation.Category().Description)
		fmt.Printf("%v: %v\n", missingidentityproviderisolation.Category().Id, missingidentityproviderisolation.Category().Description)
		fmt.Printf("%v: %v\n", missingidentitystore.Category().Id, missingidentitystore.Category().Description)
		fmt.Printf("%v: %v\n", missingnetworksegmentation.Category().Id, missingnetworksegmentation.Category().Description)
		fmt.Printf("%v: %v\n", missingvault.Category().Id, missingvault.Category().Description)
		fmt.Printf("%v: %v\n", missingvaultisolation.Category().Id, missingvaultisolation.Category().Description)
		fmt.Printf("%v: %v\n", missingwaf.Category().Id, missingwaf.Category().Description)
		fmt.Printf("%v: %v\n", mixedtargetsonsharedruntime.Category().Id, mixedtargetsonsharedruntime.Category().Description)
		fmt.Printf("%v: %v\n", pathtraversal.Category().Id, pathtraversal.Category().Description)
		fmt.Printf("%v: %v\n", pushinsteadofpulldeployment.Category().Id, pushinsteadofpulldeployment.Category().Description)
		fmt.Printf("%v: %v\n", searchqueryinjection.Category().Id, searchqueryinjection.Category().Description)
		fmt.Printf("%v: %v\n", serversiderequestforgery.Category().Id, serversiderequestforgery.Category().Description)
		fmt.Printf("%v: %v\n", serviceregistrypoisoning.Category().Id, serviceregistrypoisoning.Category().Description)
		fmt.Printf("%v: %v\n", sqlnosqlinjection.Category().Id, sqlnosqlinjection.Category().Description)
		fmt.Printf("%v: %v\n", uncheckeddeployment.Category().Id, uncheckeddeployment.Category().Description)
		fmt.Printf("%v: %v\n", unencryptedasset.Category().Id, unencryptedasset.Category().Description)
		fmt.Printf("%v: %v\n", unencryptedcommunication.Category().Id, unencryptedcommunication.Category().Description)
		fmt.Printf("%v: %v\n", unguardedaccessfrominternet.Category().Id, unguardedaccessfrominternet.Category().Description)
		fmt.Printf("%v: %v\n", unguardeddirectdatastoreaccess.Category().Id, unguardeddirectdatastoreaccess.Category().Description)
		fmt.Printf("%v: %v\n", unnecessarycommunicationlink.Category().Id, unnecessarycommunicationlink.Category().Description)
		fmt.Printf("%v: %v\n", unnecessarydataasset.Category().Id, unnecessarydataasset.Category().Description)
		fmt.Printf("%v: %v\n", unnecessarydatatransfer.Category().Id, unnecessarydatatransfer.Category().Description)
		fmt.Printf("%v: %v\n", unnecessarytechnicalasset.Category().Id, unnecessarytechnicalasset.Category().Description)
		fmt.Printf("%v: %v\n", untrusteddeserialization.Category().Id, untrusteddeserialization.Category().Description)
		fmt.Printf("%v: %v\n", wrongcommunicationlinkcontent.Category().Id, wrongcommunicationlinkcontent.Category().Description)
		fmt.Printf("%v: %v\n", wrongtrustboundarycontent.Category().Id, wrongtrustboundarycontent.Category().Description)
		fmt.Printf("%v: %v\n", xmlexternalentity.Category().Id, xmlexternalentity.Category().Description)
		fmt.Println()
		os.Exit(0)
	}
	if *print3rdParty {
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
		fmt.Println("Kudos & Credits to the following open-source projects:")
		fmt.Println(" - golang (Google Go License): https://golang.org/LICENSE")
		fmt.Println(" - go-yaml (MIT License): https://github.com/go-yaml/yaml/blob/v3/LICENSE")
		fmt.Println(" - graphviz (CPL License): https://graphviz.gitlab.io/license/")
		fmt.Println(" - gofpdf (MIT License): https://github.com/jung-kurt/gofpdf/blob/master/LICENSE")
		fmt.Println(" - go-chart (MIT License): https://github.com/wcharczuk/go-chart/blob/master/LICENSE")
		fmt.Println(" - excelize (BSD License): https://github.com/qax-os/excelize/blob/master/LICENSE")
		fmt.Println(" - graphics-go (BSD License): https://github.com/BurntSushi/graphics-go/blob/master/LICENSE")
		fmt.Println(" - google-uuid (BSD License): https://github.com/google/uuid/blob/master/LICENSE")
		fmt.Println(" - gin-gonic (MIT License): https://github.com/gin-gonic/gin/blob/master/LICENSE")
		fmt.Println(" - swagger-ui (Apache License): https://swagger.io/license/")
		fmt.Println()
		os.Exit(0)
	}
	if *license {
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
		content, err := os.ReadFile(filepath.Join(*context.appFolder, "LICENSE.txt"))
		checkErr(err)
		fmt.Print(string(content))
		fmt.Println()
		os.Exit(0)
	}
	if *context.testParseModel {
		testError := context.goTestParseModel()
		if testError != nil {
			log.Fatalf("parse test failed: %v", testError)
			return
		}
		fmt.Println("Parse test successful.")
		fmt.Println()
		os.Exit(0)
	}
	if *context.createExampleModel {
		exampleError := context.createExampleModelFile()
		if exampleError != nil {
			log.Fatalf("Unable to copy example model: %v", exampleError)
			return
		}
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
		fmt.Println("An example model was created named threagile-example-model.yaml in the output directory.")
		fmt.Println()
		fmt.Println(docs.Examples)
		fmt.Println()
		os.Exit(0)
	}
	if *context.createStubModel {
		stubError := context.createStubModelFile()
		if stubError != nil {
			log.Fatalf("Unable to copy stub model: %v", stubError)
			return
		}
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
		fmt.Println("A minimal stub model was created named threagile-stub-model.yaml in the output directory.")
		fmt.Println()
		fmt.Println(docs.Examples)
		fmt.Println()
		os.Exit(0)
	}
	if *context.createEditingSupport {
		supportError := context.createEditingSupportFiles()
		if supportError != nil {
			log.Fatalf("Unable to copy editing support files: %v", supportError)
			return
		}
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
		fmt.Println("The following files were created in the output directory:")
		fmt.Println(" - schema.json")
		fmt.Println(" - live-templates.txt")
		fmt.Println()
		fmt.Println("For a perfect editing experience within your IDE of choice you can easily get " +
			"model syntax validation and autocompletion (very handy for enum values) as well as live templates: " +
			"Just import the schema.json into your IDE and assign it as \"schema\" to each Threagile YAML file. " +
			"Also try to import individual parts from the live-templates.txt file into your IDE as live editing templates.")
		fmt.Println()
		os.Exit(0)
	}

	context.ServerMode = (*context.serverPort > 0)
}

// explainTypes prints and explanation block and a header
func printExplainTypes(title string, value []types.TypeEnum) {
	fmt.Println(title)
	for _, candidate := range value {
		fmt.Printf("\t %v: %v\n", candidate, candidate.Explain())
	}
}

func (context *Context) createExampleModelFile() error {
	_, err := copyFile(filepath.Join(*context.appFolder, "threagile-example-model.yaml"), filepath.Join(*context.outputDir, "threagile-example-model.yaml"))
	if err == nil {
		return nil
	}

	_, altError := copyFile(filepath.Join(*context.appFolder, "threagile.yaml"), filepath.Join(*context.outputDir, "threagile-example-model.yaml"))
	if altError != nil {
		return err
	}

	return nil
}

func (context *Context) createStubModelFile() error {
	_, err := copyFile(filepath.Join(*context.appFolder, "threagile-stub-model.yaml"), filepath.Join(*context.outputDir, "threagile-stub-model.yaml"))
	if err == nil {
		return nil
	}

	_, altError := copyFile(filepath.Join(*context.appFolder, "threagile.yaml"), filepath.Join(*context.outputDir, "threagile-stub-model.yaml"))
	if altError != nil {
		return err
	}

	return nil
}

func (context *Context) createEditingSupportFiles() error {
	_, schemaError := copyFile(filepath.Join(*context.appFolder, "schema.json"), filepath.Join(*context.outputDir, "schema.json"))
	if schemaError != nil {
		return schemaError
	}

	_, templateError := copyFile(filepath.Join(*context.appFolder, "live-templates.txt"), filepath.Join(*context.outputDir, "live-templates.txt"))
	return templateError
}

func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer func() { _ = source.Close() }()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer func() { _ = destination.Close() }()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func (context *Context) goTestParseModel() error {
	flatModelFile := filepath.Join("test", "all.yaml")
	flatModel := *new(input.ModelInput).Defaults()
	flatLoadError := flatModel.Load(flatModelFile)
	if flatLoadError != nil {
		return fmt.Errorf("unable to parse model yaml %q: %v", flatModelFile, flatLoadError)
	}

	sort.Strings(flatModel.TagsAvailable)
	flatModel.TagsAvailable = []string{strings.Join(flatModel.TagsAvailable, ", ")}

	flatData, flatMarshalError := json.MarshalIndent(flatModel, "", "  ")
	if flatMarshalError != nil {
		return fmt.Errorf("unable to print model yaml %q: %v", flatModelFile, flatMarshalError)
	}

	splitModelFile := filepath.Join("test", "main.yaml")
	splitModel := *new(input.ModelInput).Defaults()
	splitLoadError := splitModel.Load(splitModelFile)
	if splitLoadError != nil {
		return fmt.Errorf("unable to parse model yaml %q: %v", splitModelFile, splitLoadError)
	}

	sort.Strings(splitModel.TagsAvailable)
	splitModel.TagsAvailable = []string{strings.Join(splitModel.TagsAvailable, ", ")}

	splitModel.Includes = flatModel.Includes
	splitData, splitMarshalError := json.MarshalIndent(splitModel, "", "  ")
	if splitMarshalError != nil {
		return fmt.Errorf("unable to print model yaml %q: %v", splitModelFile, splitMarshalError)
	}

	if string(flatData) != string(splitData) {
		return fmt.Errorf("parsing split model files is broken; diff: %v", textdiff.Unified(flatModelFile, splitModelFile, string(flatData), string(splitData)))
	}

	return nil
}

func (context *Context) applyWildcardRiskTrackingEvaluation() {
	if *context.verbose {
		fmt.Println("Executing risk tracking evaluation")
	}
	for syntheticRiskIdPattern, riskTracking := range context.deferredRiskTrackingDueToWildcardMatching {
		if *context.verbose {
			fmt.Println("Applying wildcard risk tracking for risk id: " + syntheticRiskIdPattern)
		}

		foundSome := false
		var matchingRiskIdExpression = regexp.MustCompile(strings.ReplaceAll(regexp.QuoteMeta(syntheticRiskIdPattern), `\*`, `[^@]+`))
		for syntheticRiskId := range context.parsedModel.GeneratedRisksBySyntheticId {
			if matchingRiskIdExpression.Match([]byte(syntheticRiskId)) && context.hasNotYetAnyDirectNonWildcardRiskTracking(syntheticRiskId) {
				foundSome = true
				context.parsedModel.RiskTracking[syntheticRiskId] = model.RiskTracking{
					SyntheticRiskId: strings.TrimSpace(syntheticRiskId),
					Justification:   riskTracking.Justification,
					CheckedBy:       riskTracking.CheckedBy,
					Ticket:          riskTracking.Ticket,
					Status:          riskTracking.Status,
					Date:            riskTracking.Date,
				}
			}
		}

		if !foundSome {
			if *context.ignoreOrphanedRiskTracking {
				fmt.Println("WARNING: Wildcard risk tracking does not match any risk id: " + syntheticRiskIdPattern)
			} else {
				panic(errors.New("wildcard risk tracking does not match any risk id: " + syntheticRiskIdPattern))
			}
		}
	}
}

func (context *Context) hasNotYetAnyDirectNonWildcardRiskTracking(syntheticRiskId string) bool {
	if _, ok := context.parsedModel.RiskTracking[syntheticRiskId]; ok {
		return false
	}
	return true
}

func (context *Context) writeDataAssetDiagramGraphvizDOT(diagramFilenameDOT string, dpi int) *os.File {
	if *context.verbose {
		fmt.Println("Writing data asset diagram input")
	}
	var dotContent strings.Builder
	dotContent.WriteString("digraph generatedModel { concentrate=true \n")

	// Metadata init ===============================================================================
	dotContent.WriteString(`	graph [
		dpi=` + strconv.Itoa(dpi) + `
		fontname="Verdana"
		labelloc="c"
		fontsize="20"
		splines=false
		rankdir="LR"
		nodesep=1.0
		ranksep=3.0
        outputorder="nodesfirst"
	];
	node [
		fontcolor="white"
		fontname="Verdana"
		fontsize="20"
	];
	edge [
		shape="none"
		fontname="Verdana"
		fontsize="18"
	];
`)

	// Technical Assets ===============================================================================
	techAssets := make([]model.TechnicalAsset, 0)
	for _, techAsset := range context.parsedModel.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(model.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		if len(technicalAsset.DataAssetsStored) > 0 || len(technicalAsset.DataAssetsProcessed) > 0 {
			dotContent.WriteString(context.makeTechAssetNode(technicalAsset, true))
			dotContent.WriteString("\n")
		}
	}

	// Data Assets ===============================================================================
	dataAssets := make([]model.DataAsset, 0)
	for _, dataAsset := range context.parsedModel.DataAssets {
		dataAssets = append(dataAssets, dataAsset)
	}

	model.SortByDataAssetDataBreachProbabilityAndTitle(&context.parsedModel, dataAssets)
	for _, dataAsset := range dataAssets {
		dotContent.WriteString(context.makeDataAssetNode(dataAsset))
		dotContent.WriteString("\n")
	}

	// Data Asset to Tech Asset links ===============================================================================
	for _, technicalAsset := range techAssets {
		for _, sourceId := range technicalAsset.DataAssetsStored {
			targetId := technicalAsset.Id
			dotContent.WriteString("\n")
			dotContent.WriteString(hash(sourceId) + " -> " + hash(targetId) +
				` [ color="blue" style="solid" ];`)
			dotContent.WriteString("\n")
		}
		for _, sourceId := range technicalAsset.DataAssetsProcessed {
			if !contains(technicalAsset.DataAssetsStored, sourceId) { // here only if not already drawn above
				targetId := technicalAsset.Id
				dotContent.WriteString("\n")
				dotContent.WriteString(hash(sourceId) + " -> " + hash(targetId) +
					` [ color="#666666" style="dashed" ];`)
				dotContent.WriteString("\n")
			}
		}
	}

	dotContent.WriteString("}")

	// Write the DOT file
	file, err := os.Create(diagramFilenameDOT)
	checkErr(err)
	defer func() { _ = file.Close() }()
	_, err = fmt.Fprintln(file, dotContent.String())
	checkErr(err)
	return file
}

func (context *Context) makeTechAssetNode(technicalAsset model.TechnicalAsset, simplified bool) string {
	if simplified {
		color := colors.RgbHexColorOutOfScope()
		if !technicalAsset.OutOfScope {
			generatedRisks := technicalAsset.GeneratedRisks(&context.parsedModel)
			switch model.HighestSeverityStillAtRisk(&context.parsedModel, generatedRisks) {
			case types.CriticalSeverity:
				color = colors.RgbHexColorCriticalRisk()
			case types.HighSeverity:
				color = colors.RgbHexColorHighRisk()
			case types.ElevatedSeverity:
				color = colors.RgbHexColorElevatedRisk()
			case types.MediumSeverity:
				color = colors.RgbHexColorMediumRisk()
			case types.LowSeverity:
				color = colors.RgbHexColorLowRisk()
			default:
				color = "#444444" // since black is too dark here as fill color
			}
			if len(model.ReduceToOnlyStillAtRisk(&context.parsedModel, generatedRisks)) == 0 {
				color = "#444444" // since black is too dark here as fill color
			}
		}
		return "  " + hash(technicalAsset.Id) + ` [ shape="box" style="filled" fillcolor="` + color + `"
				label=<<b>` + encode(technicalAsset.Title) + `</b>> penwidth="3.0" color="` + color + `" ];
				`
	} else {
		var shape, title string
		var lineBreak = ""
		switch technicalAsset.Type {
		case types.ExternalEntity:
			shape = "box"
			title = technicalAsset.Title
		case types.Process:
			shape = "ellipse"
			title = technicalAsset.Title
		case types.Datastore:
			shape = "cylinder"
			title = technicalAsset.Title
			if technicalAsset.Redundant {
				lineBreak = "<br/>"
			}
		}

		if technicalAsset.UsedAsClientByHuman {
			shape = "octagon"
		}

		// RAA = Relative Attacker Attractiveness
		raa := technicalAsset.RAA
		var attackerAttractivenessLabel string
		if technicalAsset.OutOfScope {
			attackerAttractivenessLabel = "<font point-size=\"15\" color=\"#603112\">RAA: out of scope</font>"
		} else {
			attackerAttractivenessLabel = "<font point-size=\"15\" color=\"#603112\">RAA: " + fmt.Sprintf("%.0f", raa) + " %</font>"
		}

		compartmentBorder := "0"
		if technicalAsset.MultiTenant {
			compartmentBorder = "1"
		}

		return "  " + hash(technicalAsset.Id) + ` [
	label=<<table border="0" cellborder="` + compartmentBorder + `" cellpadding="2" cellspacing="0"><tr><td><font point-size="15" color="` + colors.DarkBlue + `">` + lineBreak + technicalAsset.Technology.String() + `</font><br/><font point-size="15" color="` + colors.LightGray + `">` + technicalAsset.Size.String() + `</font></td></tr><tr><td><b><font color="` + technicalAsset.DetermineLabelColor(&context.parsedModel) + `">` + encode(title) + `</font></b><br/></td></tr><tr><td>` + attackerAttractivenessLabel + `</td></tr></table>>
	shape=` + shape + ` style="` + technicalAsset.DetermineShapeBorderLineStyle() + `,` + technicalAsset.DetermineShapeStyle() + `" penwidth="` + technicalAsset.DetermineShapeBorderPenWidth(&context.parsedModel) + `" fillcolor="` + technicalAsset.DetermineShapeFillColor(&context.parsedModel) + `"
	peripheries=` + strconv.Itoa(technicalAsset.DetermineShapePeripheries()) + `
	color="` + technicalAsset.DetermineShapeBorderColor(&context.parsedModel) + "\"\n  ]; "
	}
}

func (context *Context) makeDataAssetNode(dataAsset model.DataAsset) string {
	var color string
	switch dataAsset.IdentifiedDataBreachProbabilityStillAtRisk(&context.parsedModel) {
	case types.Probable:
		color = colors.RgbHexColorHighRisk()
	case types.Possible:
		color = colors.RgbHexColorMediumRisk()
	case types.Improbable:
		color = colors.RgbHexColorLowRisk()
	default:
		color = "#444444" // since black is too dark here as fill color
	}
	if !dataAsset.IsDataBreachPotentialStillAtRisk(&context.parsedModel) {
		color = "#444444" // since black is too dark here as fill color
	}
	return "  " + hash(dataAsset.Id) + ` [ label=<<b>` + encode(dataAsset.Title) + `</b>> penwidth="3.0" style="filled" fillcolor="` + color + `" color="` + color + "\"\n  ]; "
}

func (context *Context) renderDataFlowDiagramGraphvizImage(dotFile *os.File, targetDir string) {
	if *context.verbose {
		fmt.Println("Rendering data flow diagram input")
	}
	// tmp files
	tmpFileDOT, err := os.CreateTemp(*context.tempFolder, "diagram-*-.gv")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFileDOT.Name()) }()

	tmpFilePNG, err := os.CreateTemp(*context.tempFolder, "diagram-*-.png")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()

	// copy into tmp file as input
	input, err := os.ReadFile(dotFile.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(tmpFileDOT.Name(), input, 0644)
	if err != nil {
		fmt.Println("Error creating", tmpFileDOT.Name())
		fmt.Println(err)
		return
	}

	// exec
	cmd := exec.Command(filepath.Join(*context.binFolder, context.graphvizDataFlowDiagramConversionCall), tmpFileDOT.Name(), tmpFilePNG.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(errors.New("graph rendering call failed with error:" + err.Error()))
	}
	// copy into resulting file
	input, err = os.ReadFile(tmpFilePNG.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(filepath.Join(targetDir, context.dataFlowDiagramFilenamePNG), input, 0644)
	if err != nil {
		fmt.Println("Error creating", context.dataFlowDiagramFilenamePNG)
		fmt.Println(err)
		return
	}
}

func (context *Context) renderDataAssetDiagramGraphvizImage(dotFile *os.File, targetDir string) { // TODO dedupe with other render...() method here
	if *context.verbose {
		fmt.Println("Rendering data asset diagram input")
	}
	// tmp files
	tmpFileDOT, err := os.CreateTemp(*context.tempFolder, "diagram-*-.gv")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFileDOT.Name()) }()

	tmpFilePNG, err := os.CreateTemp(*context.tempFolder, "diagram-*-.png")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()

	// copy into tmp file as input
	input, err := os.ReadFile(dotFile.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(tmpFileDOT.Name(), input, 0644)
	if err != nil {
		fmt.Println("Error creating", tmpFileDOT.Name())
		fmt.Println(err)
		return
	}

	// exec
	cmd := exec.Command(filepath.Join(*context.binFolder, context.graphvizDataAssetDiagramConversionCall), tmpFileDOT.Name(), tmpFilePNG.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(errors.New("graph rendering call failed with error: " + err.Error()))
	}
	// copy into resulting file
	input, err = os.ReadFile(tmpFilePNG.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(filepath.Join(targetDir, context.dataAssetDiagramFilenamePNG), input, 0644)
	if err != nil {
		fmt.Println("Error creating", context.dataAssetDiagramFilenamePNG)
		fmt.Println(err)
		return
	}
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func lowerCaseAndTrim(tags []string) []string {
	for i := range tags {
		tags[i] = strings.ToLower(strings.TrimSpace(tags[i]))
	}
	return tags
}

func (context *Context) checkTags(tags []string, where string) []string {
	var tagsUsed = make([]string, 0)
	if tags != nil {
		tagsUsed = make([]string, len(tags))
		for i, parsedEntry := range tags {
			referencedTag := fmt.Sprintf("%v", parsedEntry)
			context.checkTagExists(referencedTag, where)
			tagsUsed[i] = referencedTag
		}
	}
	return tagsUsed
}

func (context *Context) checkTagExists(referencedTag, where string) {
	if !contains(context.parsedModel.TagsAvailable, referencedTag) {
		panic(errors.New("missing referenced tag in overall tag list at " + where + ": " + referencedTag))
	}
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func withDefault(value string, defaultWhenEmpty string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) > 0 && trimmed != "<nil>" {
		return trimmed
	}
	return strings.TrimSpace(defaultWhenEmpty)
}

func hash(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%v", h.Sum32())
}

func encode(value string) string {
	return strings.ReplaceAll(value, "&", "&amp;")
}
