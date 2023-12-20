package unchecked_deployment

import (
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/security/types"
)

func Rule() model.CustomRiskRule {
	return model.CustomRiskRule{
		Category:      Category,
		SupportedTags: SupportedTags,
		GenerateRisks: GenerateRisks,
	}
}

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unchecked-deployment",
		Title: "Unchecked Deployment",
		Description: "For each build-pipeline component Unchecked Deployment risks might arise when the build-pipeline " +
			"does not include established DevSecOps best-practices. DevSecOps best-practices scan as part of CI/CD pipelines for " +
			"vulnerabilities in source- or byte-code, dependencies, container layers, and dynamically against running test systems. " +
			"There are several open-source and commercial tools existing in the categories DAST, SAST, and IAST.",
		Impact: "If this risk remains unmitigated, vulnerabilities in custom-developed software or their dependencies " +
			"might not be identified during continuous deployment cycles.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Apply DevSecOps best-practices and use scanning tools to identify vulnerabilities in source- or byte-code," +
			"dependencies, container layers, and optionally also via dynamic scans against running test systems.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Architecture,
		STRIDE:         types.Tampering,
		DetectionLogic: "All development-relevant technical assets.",
		RiskAssessment: "The risk rating depends on the highest rating of the technical assets and data assets processed by deployment-receiving targets.",
		FalsePositives: "When the build-pipeline does not build any software components it can be considered a false positive " +
			"after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1127,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks(input *model.ParsedModel) []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.Technology.IsDevelopmentRelevant() {
			risks = append(risks, createRisk(input, technicalAsset))
		}
	}
	return risks
}

func createRisk(input *model.ParsedModel, technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Unchecked Deployment</b> risk at <b>" + technicalAsset.Title + "</b>"
	// impact is depending on highest rating
	impact := types.LowImpact
	// data breach at all deployment targets
	uniqueDataBreachTechnicalAssetIDs := make(map[string]interface{})
	uniqueDataBreachTechnicalAssetIDs[technicalAsset.Id] = true
	for _, codeDeploymentTargetCommLink := range technicalAsset.CommunicationLinks {
		if codeDeploymentTargetCommLink.Usage == types.DevOps {
			for _, dataAssetID := range codeDeploymentTargetCommLink.DataAssetsSent {
				// it appears to be code when elevated integrity rating of sent data asset
				if input.DataAssets[dataAssetID].Integrity >= types.Important {
					// here we've got a deployment target which has its data assets at risk via deployment of backdoored code
					uniqueDataBreachTechnicalAssetIDs[codeDeploymentTargetCommLink.TargetId] = true
					targetTechAsset := input.TechnicalAssets[codeDeploymentTargetCommLink.TargetId]
					if targetTechAsset.HighestConfidentiality(input) >= types.Confidential ||
						targetTechAsset.HighestIntegrity(input) >= types.Critical ||
						targetTechAsset.HighestAvailability(input) >= types.Critical {
						impact = types.MediumImpact
					}
					break
				}
			}
		}
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
	}
	// create risk
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
