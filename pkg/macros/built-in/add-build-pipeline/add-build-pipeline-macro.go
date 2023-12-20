package add_build_pipeline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/security/types"
)

func GetMacroDetails() macros.MacroDetails {
	return macros.MacroDetails{
		ID:    "add-build-pipeline",
		Title: "Add Build Pipeline",
		Description: "This model macro adds a build pipeline (development client, build pipeline, artifact registry, container image registry, " +
			"source code repository, etc.) to the model.",
	}
}

var macroState = make(map[string][]string)
var questionsAnswered = make([]string, 0)
var codeInspectionUsed, containerTechUsed, withinTrustBoundary, createNewTrustBoundary bool

const createNewTrustBoundaryLabel = "CREATE NEW TRUST BOUNDARY"

var pushOrPull = []string{
	"Push-based Deployment (build pipeline deploys towards target asset)",
	"Pull-based Deployment (deployment target asset fetches deployment from registry)",
}

// TODO add question for type of machine (either physical, virtual, container, etc.)

func GetNextQuestion(model *model.ParsedModel) (nextQuestion macros.MacroQuestion, err error) {
	counter := len(questionsAnswered)
	if counter > 3 && !codeInspectionUsed {
		counter++
	}
	if counter > 5 && !containerTechUsed {
		counter += 2
	}
	if counter > 12 && !withinTrustBoundary {
		counter++
	}
	if counter > 13 && !createNewTrustBoundary {
		counter++
	}
	switch counter {
	case 0:
		return macros.MacroQuestion{
			ID:              "source-repository",
			Title:           "What product is used as the sourcecode repository?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Git",
		}, nil
	case 1:
		return macros.MacroQuestion{
			ID:              "build-pipeline",
			Title:           "What product is used as the build pipeline?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Jenkins",
		}, nil
	case 2:
		return macros.MacroQuestion{
			ID:              "artifact-registry",
			Title:           "What product is used as the artifact registry?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Nexus",
		}, nil
	case 3:
		return macros.MacroQuestion{
			ID:              "code-inspection-used",
			Title:           "Are code inspection platforms (like SonarQube) used?",
			Description:     "This affects whether code inspection platform are added.",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "Yes",
		}, nil
	case 4:
		return macros.MacroQuestion{
			ID:              "code-inspection-platform",
			Title:           "What product is used as the code inspection platform?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "SonarQube",
		}, nil
	case 5:
		return macros.MacroQuestion{
			ID:              "container-technology-used",
			Title:           "Is container technology (like Docker) used?",
			Description:     "This affects whether container registries are added.",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "Yes",
		}, nil
	case 6:
		return macros.MacroQuestion{
			ID:              "container-registry",
			Title:           "What product is used as the container registry?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Docker",
		}, nil
	case 7:
		return macros.MacroQuestion{
			ID:              "container-platform",
			Title:           "What product is used as the container platform (for orchestration and runtime)?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Kubernetes",
		}, nil
	case 8:
		return macros.MacroQuestion{
			ID:              "internet",
			Title:           "Are build pipeline components exposed on the internet?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "No",
		}, nil
	case 9:
		return macros.MacroQuestion{
			ID:              "multi-tenant",
			Title:           "Are build pipeline components used by multiple tenants?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "No",
		}, nil
	case 10:
		return macros.MacroQuestion{
			ID:              "encryption",
			Title:           "Are build pipeline components encrypted?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "No",
		}, nil
	case 11:
		possibleAnswers := make([]string, 0)
		for id := range model.TechnicalAssets {
			possibleAnswers = append(possibleAnswers, id)
		}
		sort.Strings(possibleAnswers)
		if len(possibleAnswers) > 0 {
			return macros.MacroQuestion{
				ID:              "deploy-targets",
				Title:           "Select all technical assets where the build pipeline deploys to:",
				Description:     "This affects the communication links being generated.",
				PossibleAnswers: possibleAnswers,
				MultiSelect:     true,
				DefaultAnswer:   "",
			}, nil
		}
	case 12:
		return macros.MacroQuestion{
			ID:              "within-trust-boundary",
			Title:           "Are the server-side components of the build pipeline components within a network trust boundary?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "Yes",
		}, nil
	case 13:
		possibleAnswers := []string{createNewTrustBoundaryLabel}
		for id, trustBoundary := range model.TrustBoundaries {
			if trustBoundary.Type.IsNetworkBoundary() {
				possibleAnswers = append(possibleAnswers, id)
			}
		}
		sort.Strings(possibleAnswers)
		return macros.MacroQuestion{
			ID:              "selected-trust-boundary",
			Title:           "Choose from the list of existing network trust boundaries or create a new one?",
			Description:     "",
			PossibleAnswers: possibleAnswers,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	case 14:
		return macros.MacroQuestion{
			ID:          "new-trust-boundary-type",
			Title:       "Of which type shall the new trust boundary be?",
			Description: "",
			PossibleAnswers: []string{types.NetworkOnPrem.String(),
				types.NetworkDedicatedHoster.String(),
				types.NetworkVirtualLAN.String(),
				types.NetworkCloudProvider.String(),
				types.NetworkCloudSecurityGroup.String(),
				types.NetworkPolicyNamespaceIsolation.String()},
			MultiSelect:   false,
			DefaultAnswer: types.NetworkOnPrem.String(),
		}, nil
	case 15:
		return macros.MacroQuestion{
			ID:              "push-or-pull",
			Title:           "What type of deployment strategy is used?",
			Description:     "Push-based deployments are more classic ones and pull-based are more GitOps-like ones.",
			PossibleAnswers: pushOrPull,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	case 16:
		return macros.MacroQuestion{
			ID:              "owner",
			Title:           "Who is the owner of the build pipeline and runtime assets?",
			Description:     "This name affects the technical asset's and data asset's owner.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	}
	return macros.NoMoreQuestions(), nil
}

func ApplyAnswer(questionID string, answer ...string) (message string, validResult bool, err error) {
	macroState[questionID] = answer
	questionsAnswered = append(questionsAnswered, questionID)
	if questionID == "code-inspection-used" {
		codeInspectionUsed = strings.ToLower(macroState["code-inspection-used"][0]) == "yes"
	} else if questionID == "container-technology-used" {
		containerTechUsed = strings.ToLower(macroState["container-technology-used"][0]) == "yes"
	} else if questionID == "within-trust-boundary" {
		withinTrustBoundary = strings.ToLower(macroState["within-trust-boundary"][0]) == "yes"
	} else if questionID == "selected-trust-boundary" {
		createNewTrustBoundary = strings.ToLower(macroState["selected-trust-boundary"][0]) == strings.ToLower(createNewTrustBoundaryLabel)
	}
	return "Answer processed", true, nil
}

func GoBack() (message string, validResult bool, err error) {
	if len(questionsAnswered) == 0 {
		return "Cannot go back further", false, nil
	}
	lastQuestionID := questionsAnswered[len(questionsAnswered)-1]
	questionsAnswered = questionsAnswered[:len(questionsAnswered)-1]
	delete(macroState, lastQuestionID)
	return "Undo successful", true, nil
}

func GetFinalChangeImpact(modelInput *input.ModelInput, model *model.ParsedModel) (changes []string, message string, validResult bool, err error) {
	changeLogCollector := make([]string, 0)
	message, validResult, err = applyChange(modelInput, model, &changeLogCollector, true)
	return changeLogCollector, message, validResult, err
}

func Execute(modelInput *input.ModelInput, model *model.ParsedModel) (message string, validResult bool, err error) {
	changeLogCollector := make([]string, 0)
	message, validResult, err = applyChange(modelInput, model, &changeLogCollector, false)
	return message, validResult, err
}

func applyChange(modelInput *input.ModelInput, parsedModel *model.ParsedModel, changeLogCollector *[]string, dryRun bool) (message string, validResult bool, err error) {
	var serverSideTechAssets = make([]string, 0)
	// ################################################
	input.AddTagToModelInput(modelInput, macroState["source-repository"][0], dryRun, changeLogCollector)
	input.AddTagToModelInput(modelInput, macroState["build-pipeline"][0], dryRun, changeLogCollector)
	input.AddTagToModelInput(modelInput, macroState["artifact-registry"][0], dryRun, changeLogCollector)
	if containerTechUsed {
		input.AddTagToModelInput(modelInput, macroState["container-registry"][0], dryRun, changeLogCollector)
		input.AddTagToModelInput(modelInput, macroState["container-platform"][0], dryRun, changeLogCollector)
	}
	if codeInspectionUsed {
		input.AddTagToModelInput(modelInput, macroState["code-inspection-platform"][0], dryRun, changeLogCollector)
	}

	sourceRepoID := model.MakeID(macroState["source-repository"][0]) + "-sourcecode-repository"
	buildPipelineID := model.MakeID(macroState["build-pipeline"][0]) + "-build-pipeline"
	artifactRegistryID := model.MakeID(macroState["artifact-registry"][0]) + "-artifact-registry"
	containerRepoID, containerPlatformID, containerSharedRuntimeID := "", "", ""
	if containerTechUsed {
		containerRepoID = model.MakeID(macroState["container-registry"][0]) + "-container-registry"
		containerPlatformID = model.MakeID(macroState["container-platform"][0]) + "-container-platform"
		containerSharedRuntimeID = model.MakeID(macroState["container-platform"][0]) + "-container-runtime"
	}
	codeInspectionPlatformID := ""
	if codeInspectionUsed {
		codeInspectionPlatformID = model.MakeID(macroState["code-inspection-platform"][0]) + "-code-inspection-platform"
	}
	owner := macroState["owner"][0]

	if _, exists := parsedModel.DataAssets["Sourcecode"]; !exists {
		//fmt.Println("Adding data asset:", "sourcecode") // ################################################
		dataAsset := input.InputDataAsset{
			ID:              "sourcecode",
			Description:     "Sourcecode to build the application components from",
			Usage:           types.DevOps.String(),
			Tags:            []string{},
			Origin:          "",
			Owner:           owner,
			Quantity:        types.Few.String(),
			Confidentiality: types.Confidential.String(),
			Integrity:       types.Critical.String(),
			Availability:    types.Important.String(),
			JustificationCiaRating: "Sourcecode is at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
		}
		*changeLogCollector = append(*changeLogCollector, "adding data asset: sourcecode")
		if !dryRun {
			modelInput.DataAssets["Sourcecode"] = dataAsset
		}
	}

	if _, exists := parsedModel.DataAssets["Deployment"]; !exists {
		//fmt.Println("Adding data asset:", "deployment") // ################################################
		dataAsset := input.InputDataAsset{
			ID:              "deployment",
			Description:     "Deployment unit being installed/shipped",
			Usage:           types.DevOps.String(),
			Tags:            []string{},
			Origin:          "",
			Owner:           owner,
			Quantity:        types.VeryFew.String(),
			Confidentiality: types.Confidential.String(),
			Integrity:       types.Critical.String(),
			Availability:    types.Important.String(),
			JustificationCiaRating: "Deployment units are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
		}
		*changeLogCollector = append(*changeLogCollector, "adding data asset: deployment")
		if !dryRun {
			modelInput.DataAssets["Deployment"] = dataAsset
		}
	}

	id := "development-client"
	if _, exists := parsedModel.TechnicalAssets[id]; !exists {
		//fmt.Println("Adding technical asset:", id) // ################################################
		encryption := types.NoneEncryption.String()
		if strings.ToLower(macroState["encryption"][0]) == "yes" {
			encryption = types.Transparent.String()
		}

		commLinks := make(map[string]input.InputCommunicationLink)
		commLinks["Sourcecode Repository Traffic"] = input.InputCommunicationLink{
			Target:                 sourceRepoID,
			Description:            "Sourcecode Repository Traffic",
			Protocol:               types.HTTPS.String(),
			Authentication:         types.Credentials.String(),
			Authorization:          types.EndUserIdentityPropagation.String(),
			Tags:                   []string{},
			VPN:                    false,
			IpFiltered:             false,
			Readonly:               false,
			Usage:                  types.DevOps.String(),
			DataAssetsSent:         []string{"sourcecode"},
			DataAssetsReceived:     []string{"sourcecode"},
			DiagramTweakWeight:     0,
			DiagramTweakConstraint: false,
		}
		commLinks["Build Pipeline Traffic"] = input.InputCommunicationLink{
			Target:                 buildPipelineID,
			Description:            "Build Pipeline Traffic",
			Protocol:               types.HTTPS.String(),
			Authentication:         types.Credentials.String(),
			Authorization:          types.EndUserIdentityPropagation.String(),
			Tags:                   []string{},
			VPN:                    false,
			IpFiltered:             false,
			Readonly:               true,
			Usage:                  types.DevOps.String(),
			DataAssetsSent:         nil,
			DataAssetsReceived:     []string{"deployment"},
			DiagramTweakWeight:     0,
			DiagramTweakConstraint: false,
		}
		commLinks["Artifact Registry Traffic"] = input.InputCommunicationLink{
			Target:                 artifactRegistryID,
			Description:            "Artifact Registry Traffic",
			Protocol:               types.HTTPS.String(),
			Authentication:         types.Credentials.String(),
			Authorization:          types.EndUserIdentityPropagation.String(),
			Tags:                   []string{},
			VPN:                    false,
			IpFiltered:             false,
			Readonly:               true,
			Usage:                  types.DevOps.String(),
			DataAssetsSent:         nil,
			DataAssetsReceived:     []string{"deployment"},
			DiagramTweakWeight:     0,
			DiagramTweakConstraint: false,
		}
		if containerTechUsed {
			commLinks["Container Registry Traffic"] = input.InputCommunicationLink{
				Target:                 containerRepoID,
				Description:            "Container Registry Traffic",
				Protocol:               types.HTTPS.String(),
				Authentication:         types.Credentials.String(),
				Authorization:          types.EndUserIdentityPropagation.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               false,
				Usage:                  types.DevOps.String(),
				DataAssetsSent:         []string{"deployment"},
				DataAssetsReceived:     []string{"deployment"},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
			commLinks["Container Platform Traffic"] = input.InputCommunicationLink{
				Target:                 containerPlatformID,
				Description:            "Container Platform Traffic",
				Protocol:               types.HTTPS.String(),
				Authentication:         types.Credentials.String(),
				Authorization:          types.EndUserIdentityPropagation.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               false,
				Usage:                  types.DevOps.String(),
				DataAssetsSent:         []string{"deployment"},
				DataAssetsReceived:     []string{"deployment"},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
		}
		if codeInspectionUsed {
			commLinks["Code Inspection Platform Traffic"] = input.InputCommunicationLink{
				Target:                 codeInspectionPlatformID,
				Description:            "Code Inspection Platform Traffic",
				Protocol:               types.HTTPS.String(),
				Authentication:         types.Credentials.String(),
				Authorization:          types.EndUserIdentityPropagation.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               true,
				Usage:                  types.DevOps.String(),
				DataAssetsSent:         nil,
				DataAssetsReceived:     []string{"sourcecode"},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
		}

		techAsset := input.InputTechnicalAsset{
			ID:                      id,
			Description:             "Development Client",
			Type:                    types.ExternalEntity.String(),
			Usage:                   types.DevOps.String(),
			UsedAsClientByHuman:     true,
			OutOfScope:              true,
			JustificationOutOfScope: "Development client is not directly in-scope of the application.",
			Size:                    types.System.String(),
			Technology:              types.DevOpsClient.String(),
			Tags:                    []string{},
			Internet:                strings.ToLower(macroState["internet"][0]) == "yes",
			Machine:                 types.Physical.String(),
			Encryption:              encryption,
			Owner:                   owner,
			Confidentiality:         types.Confidential.String(),
			Integrity:               types.Critical.String(),
			Availability:            types.Important.String(),
			JustificationCiaRating: "Sourcecode processing components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			MultiTenant:          false,
			Redundant:            false,
			CustomDevelopedParts: false,
			DataAssetsProcessed:  []string{"sourcecode", "deployment"},
			DataAssetsStored:     []string{"sourcecode", "deployment"},
			DataFormatsAccepted:  []string{"file"},
			CommunicationLinks:   commLinks,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.TechnicalAssets["Development Client"] = techAsset
		}
	}

	id = sourceRepoID
	if _, exists := parsedModel.TechnicalAssets[id]; !exists {
		//fmt.Println("Adding technical asset:", id) // ################################################
		serverSideTechAssets = append(serverSideTechAssets, id)
		encryption := types.NoneEncryption.String()
		if strings.ToLower(macroState["encryption"][0]) == "yes" {
			encryption = types.Transparent.String()
		}
		techAsset := input.InputTechnicalAsset{
			ID:                      id,
			Description:             macroState["source-repository"][0] + " Sourcecode Repository",
			Type:                    types.Process.String(),
			Usage:                   types.DevOps.String(),
			UsedAsClientByHuman:     false,
			OutOfScope:              false,
			JustificationOutOfScope: "",
			Size:                    types.Service.String(),
			Technology:              types.SourcecodeRepository.String(),
			Tags:                    []string{input.NormalizeTag(macroState["source-repository"][0])},
			Internet:                strings.ToLower(macroState["internet"][0]) == "yes",
			Machine:                 types.Virtual.String(),
			Encryption:              encryption,
			Owner:                   owner,
			Confidentiality:         types.Confidential.String(),
			Integrity:               types.Critical.String(),
			Availability:            types.Important.String(),
			JustificationCiaRating: "Sourcecode processing components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			MultiTenant:          strings.ToLower(macroState["multi-tenant"][0]) == "yes",
			Redundant:            false,
			CustomDevelopedParts: false,
			DataAssetsProcessed:  []string{"sourcecode"},
			DataAssetsStored:     []string{"sourcecode"},
			DataFormatsAccepted:  []string{"file"},
			CommunicationLinks:   nil,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.TechnicalAssets[macroState["source-repository"][0]+" Sourcecode Repository"] = techAsset
		}
	}

	if containerTechUsed {
		id = containerRepoID
		if _, exists := parsedModel.TechnicalAssets[id]; !exists {
			//fmt.Println("Adding technical asset:", id) // ################################################
			serverSideTechAssets = append(serverSideTechAssets, id)
			encryption := types.NoneEncryption.String()
			if strings.ToLower(macroState["encryption"][0]) == "yes" {
				encryption = types.Transparent.String()
			}
			techAsset := input.InputTechnicalAsset{
				ID:                      id,
				Description:             macroState["container-registry"][0] + " Container Registry",
				Type:                    types.Process.String(),
				Usage:                   types.DevOps.String(),
				UsedAsClientByHuman:     false,
				OutOfScope:              false,
				JustificationOutOfScope: "",
				Size:                    types.Service.String(),
				Technology:              types.ArtifactRegistry.String(),
				Tags:                    []string{input.NormalizeTag(macroState["container-registry"][0])},
				Internet:                strings.ToLower(macroState["internet"][0]) == "yes",
				Machine:                 types.Virtual.String(),
				Encryption:              encryption,
				Owner:                   owner,
				Confidentiality:         types.Confidential.String(),
				Integrity:               types.Critical.String(),
				Availability:            types.Important.String(),
				JustificationCiaRating: "Container registry components are at least rated as 'critical' in terms of integrity, because any " +
					"malicious modification of it might lead to a backdoored production system.",
				MultiTenant:          strings.ToLower(macroState["multi-tenant"][0]) == "yes",
				Redundant:            false,
				CustomDevelopedParts: false,
				DataAssetsProcessed:  []string{"deployment"},
				DataAssetsStored:     []string{"deployment"},
				DataFormatsAccepted:  []string{"file"},
				CommunicationLinks:   nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
			if !dryRun {
				modelInput.TechnicalAssets[macroState["container-registry"][0]+" Container Registry"] = techAsset
			}
		}

		id = containerPlatformID
		if _, exists := parsedModel.TechnicalAssets[id]; !exists {
			//fmt.Println("Adding technical asset:", id) // ################################################
			serverSideTechAssets = append(serverSideTechAssets, id)
			encryption := types.NoneEncryption.String()
			if strings.ToLower(macroState["encryption"][0]) == "yes" {
				encryption = types.Transparent.String()
			}
			techAsset := input.InputTechnicalAsset{
				ID:                      id,
				Description:             macroState["container-platform"][0] + " Container Platform",
				Type:                    types.Process.String(),
				Usage:                   types.DevOps.String(),
				UsedAsClientByHuman:     false,
				OutOfScope:              false,
				JustificationOutOfScope: "",
				Size:                    types.System.String(),
				Technology:              types.ContainerPlatform.String(),
				Tags:                    []string{input.NormalizeTag(macroState["container-platform"][0])},
				Internet:                strings.ToLower(macroState["internet"][0]) == "yes",
				Machine:                 types.Virtual.String(),
				Encryption:              encryption,
				Owner:                   owner,
				Confidentiality:         types.Confidential.String(),
				Integrity:               types.MissionCritical.String(),
				Availability:            types.MissionCritical.String(),
				JustificationCiaRating: "Container platform components are rated as 'mission-critical' in terms of integrity and availability, because any " +
					"malicious modification of it might lead to a backdoored production system.",
				MultiTenant:          strings.ToLower(macroState["multi-tenant"][0]) == "yes",
				Redundant:            false,
				CustomDevelopedParts: false,
				DataAssetsProcessed:  []string{"deployment"},
				DataAssetsStored:     []string{"deployment"},
				DataFormatsAccepted:  []string{"file"},
				CommunicationLinks:   nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
			if !dryRun {
				modelInput.TechnicalAssets[macroState["container-platform"][0]+" Container Platform"] = techAsset
			}
		}
	}

	id = buildPipelineID
	if _, exists := parsedModel.TechnicalAssets[id]; !exists {
		//fmt.Println("Adding technical asset:", id) // ################################################
		serverSideTechAssets = append(serverSideTechAssets, id)
		encryption := types.NoneEncryption.String()
		if strings.ToLower(macroState["encryption"][0]) == "yes" {
			encryption = types.Transparent.String()
		}

		commLinks := make(map[string]input.InputCommunicationLink)
		commLinks["Sourcecode Repository Traffic"] = input.InputCommunicationLink{
			Target:                 sourceRepoID,
			Description:            "Sourcecode Repository Traffic",
			Protocol:               types.HTTPS.String(),
			Authentication:         types.Credentials.String(),
			Authorization:          types.TechnicalUser.String(),
			Tags:                   []string{},
			VPN:                    false,
			IpFiltered:             false,
			Readonly:               true,
			Usage:                  types.DevOps.String(),
			DataAssetsSent:         nil,
			DataAssetsReceived:     []string{"sourcecode"},
			DiagramTweakWeight:     0,
			DiagramTweakConstraint: false,
		}
		commLinks["Artifact Registry Traffic"] = input.InputCommunicationLink{
			Target:                 artifactRegistryID,
			Description:            "Artifact Registry Traffic",
			Protocol:               types.HTTPS.String(),
			Authentication:         types.Credentials.String(),
			Authorization:          types.TechnicalUser.String(),
			Tags:                   []string{},
			VPN:                    false,
			IpFiltered:             false,
			Readonly:               false,
			Usage:                  types.DevOps.String(),
			DataAssetsSent:         []string{"deployment"},
			DataAssetsReceived:     []string{"deployment"},
			DiagramTweakWeight:     0,
			DiagramTweakConstraint: false,
		}
		if containerTechUsed {
			commLinks["Container Registry Traffic"] = input.InputCommunicationLink{
				Target:                 containerRepoID,
				Description:            "Container Registry Traffic",
				Protocol:               types.HTTPS.String(),
				Authentication:         types.Credentials.String(),
				Authorization:          types.TechnicalUser.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               false,
				Usage:                  types.DevOps.String(),
				DataAssetsSent:         []string{"deployment"},
				DataAssetsReceived:     []string{"deployment"},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
			if macroState["push-or-pull"][0] == pushOrPull[0] { // Push
				commLinks["Container Platform Push"] = input.InputCommunicationLink{
					Target:                 containerPlatformID,
					Description:            "Container Platform Push",
					Protocol:               types.HTTPS.String(),
					Authentication:         types.Credentials.String(),
					Authorization:          types.TechnicalUser.String(),
					Tags:                   []string{},
					VPN:                    false,
					IpFiltered:             false,
					Readonly:               false,
					Usage:                  types.DevOps.String(),
					DataAssetsSent:         []string{"deployment"},
					DataAssetsReceived:     []string{"deployment"},
					DiagramTweakWeight:     0,
					DiagramTweakConstraint: false,
				}
			} else { // Pull
				commLinkPull := input.InputCommunicationLink{
					Target:                 containerRepoID,
					Description:            "Container Platform Pull",
					Protocol:               types.HTTPS.String(),
					Authentication:         types.Credentials.String(),
					Authorization:          types.TechnicalUser.String(),
					Tags:                   []string{},
					VPN:                    false,
					IpFiltered:             false,
					Readonly:               true,
					Usage:                  types.DevOps.String(),
					DataAssetsSent:         nil,
					DataAssetsReceived:     []string{"deployment"},
					DiagramTweakWeight:     0,
					DiagramTweakConstraint: false,
				}
				if !dryRun {
					titleOfTargetAsset := macroState["container-platform"][0] + " Container Platform"
					containerPlatform := modelInput.TechnicalAssets[titleOfTargetAsset]
					if containerPlatform.CommunicationLinks == nil {
						containerPlatform.CommunicationLinks = make(map[string]input.InputCommunicationLink)
					}
					containerPlatform.CommunicationLinks["Container Platform Pull"] = commLinkPull
					modelInput.TechnicalAssets[titleOfTargetAsset] = containerPlatform
				}
			}
		}
		if codeInspectionUsed {
			commLinks["Code Inspection Platform Traffic"] = input.InputCommunicationLink{
				Target:                 codeInspectionPlatformID,
				Description:            "Code Inspection Platform Traffic",
				Protocol:               types.HTTPS.String(),
				Authentication:         types.Credentials.String(),
				Authorization:          types.TechnicalUser.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               false,
				Usage:                  types.DevOps.String(),
				DataAssetsSent:         []string{"sourcecode"},
				DataAssetsReceived:     []string{},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
		}
		// The individual deployments
		for _, deployTargetID := range macroState["deploy-targets"] { // add a connection to each deployment target
			//fmt.Println("Adding deployment flow to:", deployTargetID)
			if containerTechUsed {
				if !dryRun {
					containerPlatform := modelInput.TechnicalAssets[macroState["container-platform"][0]+" Container Platform"]
					if containerPlatform.CommunicationLinks == nil {
						containerPlatform.CommunicationLinks = make(map[string]input.InputCommunicationLink)
					}
					containerPlatform.CommunicationLinks["Container Spawning ("+deployTargetID+")"] = input.InputCommunicationLink{
						Target:                 deployTargetID,
						Description:            "Container Spawning " + deployTargetID,
						Protocol:               types.ContainerSpawning.String(),
						Authentication:         types.NoneAuthentication.String(),
						Authorization:          types.NoneAuthorization.String(),
						Tags:                   []string{},
						VPN:                    false,
						IpFiltered:             false,
						Readonly:               false,
						Usage:                  types.DevOps.String(),
						DataAssetsSent:         []string{"deployment"},
						DataAssetsReceived:     nil,
						DiagramTweakWeight:     0,
						DiagramTweakConstraint: false,
					}
					modelInput.TechnicalAssets[macroState["container-platform"][0]+" Container Platform"] = containerPlatform
				}
			} else { // No Containers used
				if macroState["push-or-pull"][0] == pushOrPull[0] { // Push
					commLinks["Deployment Push ("+deployTargetID+")"] = input.InputCommunicationLink{
						Target:                 deployTargetID,
						Description:            "Deployment Push to " + deployTargetID,
						Protocol:               types.SSH.String(),
						Authentication:         types.ClientCertificate.String(),
						Authorization:          types.TechnicalUser.String(),
						Tags:                   []string{},
						VPN:                    false,
						IpFiltered:             false,
						Readonly:               false,
						Usage:                  types.DevOps.String(),
						DataAssetsSent:         []string{"deployment"},
						DataAssetsReceived:     nil,
						DiagramTweakWeight:     0,
						DiagramTweakConstraint: false,
					}
				} else { // Pull
					pullFromWhere := artifactRegistryID
					commLinkPull := input.InputCommunicationLink{
						Target:                 pullFromWhere,
						Description:            "Deployment Pull from " + deployTargetID,
						Protocol:               types.HTTPS.String(),
						Authentication:         types.Credentials.String(),
						Authorization:          types.TechnicalUser.String(),
						Tags:                   []string{},
						VPN:                    false,
						IpFiltered:             false,
						Readonly:               true,
						Usage:                  types.DevOps.String(),
						DataAssetsSent:         nil,
						DataAssetsReceived:     []string{"deployment"},
						DiagramTweakWeight:     0,
						DiagramTweakConstraint: false,
					}
					if !dryRun {
						// take care to lookup by title (as keyed in input YAML by title and only in parsed model representation by ID)
						titleOfTargetAsset := parsedModel.TechnicalAssets[deployTargetID].Title
						x := modelInput.TechnicalAssets[titleOfTargetAsset]
						if x.CommunicationLinks == nil {
							x.CommunicationLinks = make(map[string]input.InputCommunicationLink)
						}
						x.CommunicationLinks["Deployment Pull ("+deployTargetID+")"] = commLinkPull
						modelInput.TechnicalAssets[titleOfTargetAsset] = x
					}
				}
			}

			// don't forget to also add the "deployment" data asset as stored on the target
			targetAssetTitle := parsedModel.TechnicalAssets[deployTargetID].Title
			assetsStored := make([]string, 0)
			if modelInput.TechnicalAssets[targetAssetTitle].DataAssetsStored != nil {
				for _, val := range modelInput.TechnicalAssets[targetAssetTitle].DataAssetsStored {
					assetsStored = append(assetsStored, fmt.Sprintf("%v", val))
				}
			}
			mergedArrays := make([]string, 0)
			for _, val := range assetsStored {
				mergedArrays = append(mergedArrays, fmt.Sprintf("%v", val))
			}
			mergedArrays = append(mergedArrays, "deployment")
			if !dryRun {
				x := modelInput.TechnicalAssets[targetAssetTitle]
				x.DataAssetsStored = mergedArrays
				modelInput.TechnicalAssets[targetAssetTitle] = x
			}
		}

		techAsset := input.InputTechnicalAsset{
			ID:                      id,
			Description:             macroState["build-pipeline"][0] + " Build Pipeline",
			Type:                    types.Process.String(),
			Usage:                   types.DevOps.String(),
			UsedAsClientByHuman:     false,
			OutOfScope:              false,
			JustificationOutOfScope: "",
			Size:                    types.Service.String(),
			Technology:              types.BuildPipeline.String(),
			Tags:                    []string{input.NormalizeTag(macroState["build-pipeline"][0])},
			Internet:                strings.ToLower(macroState["internet"][0]) == "yes",
			Machine:                 types.Virtual.String(),
			Encryption:              encryption,
			Owner:                   owner,
			Confidentiality:         types.Confidential.String(),
			Integrity:               types.Critical.String(),
			Availability:            types.Important.String(),
			JustificationCiaRating: "Build pipeline components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			MultiTenant:          strings.ToLower(macroState["multi-tenant"][0]) == "yes",
			Redundant:            false,
			CustomDevelopedParts: false,
			DataAssetsProcessed:  []string{"sourcecode", "deployment"},
			DataAssetsStored:     []string{"sourcecode", "deployment"},
			DataFormatsAccepted:  []string{"file"},
			CommunicationLinks:   commLinks,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.TechnicalAssets[macroState["build-pipeline"][0]+" Build Pipeline"] = techAsset
		}
	}

	id = artifactRegistryID
	if _, exists := parsedModel.TechnicalAssets[id]; !exists {
		//fmt.Println("Adding technical asset:", id) // ################################################
		serverSideTechAssets = append(serverSideTechAssets, id)
		encryption := types.NoneEncryption.String()
		if strings.ToLower(macroState["encryption"][0]) == "yes" {
			encryption = types.Transparent.String()
		}
		techAsset := input.InputTechnicalAsset{
			ID:                      id,
			Description:             macroState["artifact-registry"][0] + " Artifact Registry",
			Type:                    types.Process.String(),
			Usage:                   types.DevOps.String(),
			UsedAsClientByHuman:     false,
			OutOfScope:              false,
			JustificationOutOfScope: "",
			Size:                    types.Service.String(),
			Technology:              types.ArtifactRegistry.String(),
			Tags:                    []string{input.NormalizeTag(macroState["artifact-registry"][0])},
			Internet:                strings.ToLower(macroState["internet"][0]) == "yes",
			Machine:                 types.Virtual.String(),
			Encryption:              encryption,
			Owner:                   owner,
			Confidentiality:         types.Confidential.String(),
			Integrity:               types.Critical.String(),
			Availability:            types.Important.String(),
			JustificationCiaRating: "Artifact registry components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			MultiTenant:          strings.ToLower(macroState["multi-tenant"][0]) == "yes",
			Redundant:            false,
			CustomDevelopedParts: false,
			DataAssetsProcessed:  []string{"sourcecode", "deployment"},
			DataAssetsStored:     []string{"sourcecode", "deployment"},
			DataFormatsAccepted:  []string{"file"},
			CommunicationLinks:   nil,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.TechnicalAssets[macroState["artifact-registry"][0]+" Artifact Registry"] = techAsset
		}
	}

	if codeInspectionUsed {
		id = codeInspectionPlatformID
		if _, exists := parsedModel.TechnicalAssets[id]; !exists {
			//fmt.Println("Adding technical asset:", id) // ################################################
			serverSideTechAssets = append(serverSideTechAssets, id)
			encryption := types.NoneEncryption.String()
			if strings.ToLower(macroState["encryption"][0]) == "yes" {
				encryption = types.Transparent.String()
			}
			techAsset := input.InputTechnicalAsset{
				ID:                      id,
				Description:             macroState["code-inspection-platform"][0] + " Code Inspection Platform",
				Type:                    types.Process.String(),
				Usage:                   types.DevOps.String(),
				UsedAsClientByHuman:     false,
				OutOfScope:              false,
				JustificationOutOfScope: "",
				Size:                    types.Service.String(),
				Technology:              types.CodeInspectionPlatform.String(),
				Tags:                    []string{input.NormalizeTag(macroState["code-inspection-platform"][0])},
				Internet:                strings.ToLower(macroState["internet"][0]) == "yes",
				Machine:                 types.Virtual.String(),
				Encryption:              encryption,
				Owner:                   owner,
				Confidentiality:         types.Confidential.String(),
				Integrity:               types.Important.String(),
				Availability:            types.Operational.String(),
				JustificationCiaRating: "Sourcecode inspection platforms are rated at least 'important' in terms of integrity, because any " +
					"malicious modification of it might lead to vulnerabilities found by the scanner engine not being shown.",
				MultiTenant:          strings.ToLower(macroState["multi-tenant"][0]) == "yes",
				Redundant:            false,
				CustomDevelopedParts: false,
				DataAssetsProcessed:  []string{"sourcecode"},
				DataAssetsStored:     []string{"sourcecode"},
				DataFormatsAccepted:  []string{"file"},
				CommunicationLinks:   nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
			if !dryRun {
				modelInput.TechnicalAssets[macroState["code-inspection-platform"][0]+" Code Inspection Platform"] = techAsset
			}
		}
	}

	if withinTrustBoundary {
		if createNewTrustBoundary {
			trustBoundaryType := macroState["new-trust-boundary-type"][0]
			//fmt.Println("Adding new trust boundary of type:", trustBoundaryType)
			title := "DevOps Network"
			trustBoundary := input.InputTrustBoundary{
				ID:                    "devops-network",
				Description:           "DevOps Network",
				Type:                  trustBoundaryType,
				Tags:                  []string{},
				TechnicalAssetsInside: serverSideTechAssets,
				TrustBoundariesNested: nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding trust boundary: devops-network")
			if !dryRun {
				modelInput.TrustBoundaries[title] = trustBoundary
			}
		} else {
			existingTrustBoundaryToAddTo := macroState["selected-trust-boundary"][0]
			//fmt.Println("Adding to existing trust boundary:", existingTrustBoundaryToAddTo)
			title := parsedModel.TrustBoundaries[existingTrustBoundaryToAddTo].Title
			assetsInside := make([]string, 0)
			if modelInput.TrustBoundaries[title].TechnicalAssetsInside != nil {
				values := modelInput.TrustBoundaries[title].TechnicalAssetsInside
				for _, val := range values {
					assetsInside = append(assetsInside, fmt.Sprintf("%v", val))
				}
			}
			mergedArrays := make([]string, 0)
			for _, val := range assetsInside {
				mergedArrays = append(mergedArrays, fmt.Sprintf("%v", val))
			}
			mergedArrays = append(mergedArrays, serverSideTechAssets...)
			*changeLogCollector = append(*changeLogCollector, "filling existing trust boundary: "+existingTrustBoundaryToAddTo)
			if !dryRun {
				if modelInput.TrustBoundaries == nil {
					modelInput.TrustBoundaries = make(map[string]input.InputTrustBoundary)
				}
				tb := modelInput.TrustBoundaries[title]
				tb.TechnicalAssetsInside = mergedArrays
				modelInput.TrustBoundaries[title] = tb
			}
		}
	}

	if containerTechUsed {
		// create shared runtime
		assetsRunning := make([]string, 0)
		for _, deployTargetID := range macroState["deploy-targets"] {
			assetsRunning = append(assetsRunning, deployTargetID)
		}
		title := macroState["container-platform"][0] + " Runtime"
		sharedRuntime := input.InputSharedRuntime{
			ID:                     containerSharedRuntimeID,
			Description:            title,
			Tags:                   []string{input.NormalizeTag(macroState["container-platform"][0])},
			TechnicalAssetsRunning: assetsRunning,
		}
		*changeLogCollector = append(*changeLogCollector, "adding shared runtime: "+containerSharedRuntimeID)
		if !dryRun {
			if modelInput.SharedRuntimes == nil {
				modelInput.SharedRuntimes = make(map[string]input.InputSharedRuntime)
			}
			modelInput.SharedRuntimes[title] = sharedRuntime
		}
	}

	return "Changeset valid", true, nil
}
