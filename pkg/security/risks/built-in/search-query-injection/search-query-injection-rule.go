package search_query_injection

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
		Id:    "search-query-injection",
		Title: "Search-Query Injection",
		Description: "When a search engine server is accessed Search-Query Injection risks might arise." +
			"<br><br>See for example <a href=\"https://github.com/veracode-research/solr-injection\">https://github.com/veracode-research/solr-injection</a> and " +
			"<a href=\"https://github.com/veracode-research/solr-injection/blob/master/slides/DEFCON-27-Michael-Stepankin-Apache-Solr-Injection.pdf\">https://github.com/veracode-research/solr-injection/blob/master/slides/DEFCON-27-Michael-Stepankin-Apache-Solr-Injection.pdf</a> " +
			"for more details (here related to Solr, but in general showcasing the topic of search query injections).",
		Impact: "If this risk remains unmitigated, attackers might be able to read more data from the search index and " +
			"eventually further escalate towards a deeper system penetration via code executions.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
		Action:     "Search-Query Injection Prevention",
		Mitigation: "Try to use libraries that properly encode search query meta characters in searches and don't expose the " +
			"query unfiltered to the caller. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope clients accessing search engine servers via typical search access protocols.",
		RiskAssessment: "The risk rating depends on the sensitivity of the search engine server itself and of the data assets processed or stored.",
		FalsePositives: "Server engine queries by search values not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        74,
	}
}

func GenerateRisks(input *model.ParsedModel) []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.Technology == types.SearchEngine || technicalAsset.Technology == types.SearchIndex {
			incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, incomingFlow := range incomingFlows {
				if input.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
					continue
				}
				if incomingFlow.Protocol == types.HTTP || incomingFlow.Protocol == types.HTTPS ||
					incomingFlow.Protocol == types.BINARY || incomingFlow.Protocol == types.BinaryEncrypted {
					likelihood := types.VeryLikely
					if incomingFlow.Usage == types.DevOps {
						likelihood = types.Likely
					}
					risks = append(risks, createRisk(input, technicalAsset, incomingFlow, likelihood))
				}
			}
		}
	}
	return risks
}

func SupportedTags() []string {
	return []string{}
}

func createRisk(input *model.ParsedModel, technicalAsset model.TechnicalAsset, incomingFlow model.CommunicationLink, likelihood types.RiskExploitationLikelihood) model.Risk {
	caller := input.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Search Query Injection</b> risk at <b>" + caller.Title + "</b> against search engine server <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := types.MediumImpact
	if technicalAsset.HighestConfidentiality(input) == types.StrictlyConfidential || technicalAsset.HighestIntegrity(input) == types.MissionCritical {
		impact = types.HighImpact
	} else if technicalAsset.HighestConfidentiality(input) <= types.Internal && technicalAsset.HighestIntegrity(input) == types.Operational {
		impact = types.LowImpact
	}
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           types.Probable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + caller.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
