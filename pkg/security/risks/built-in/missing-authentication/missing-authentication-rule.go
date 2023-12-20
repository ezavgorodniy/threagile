package missing_authentication

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
		Id:          "missing-authentication",
		Title:       "Missing Authentication",
		Description: "Technical assets (especially multi-tenant systems) should authenticate incoming requests when the asset processes or stores sensitive data. ",
		Impact:      "If this risk is unmitigated, attackers might be able to access or modify sensitive data in an unauthenticated way.",
		ASVS:        "V2 - Authentication Verification Requirements",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		Action:      "Authentication of Incoming Requests",
		Mitigation: "Apply an authentication method to the technical asset. To protect highly sensitive data consider " +
			"the use of two-factor authentication for human users.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets (except " + types.LoadBalancer.String() + ", " + types.ReverseProxy.String() + ", " + types.ServiceRegistry.String() + ", " + types.WAF.String() + ", " + types.IDS.String() + ", and " + types.IPS.String() + " and in-process calls) should authenticate incoming requests when the asset processes or stores " +
			"sensitive data. This is especially the case for all multi-tenant assets (there even non-sensitive ones).",
		RiskAssessment: "The risk rating (medium or high) " +
			"depends on the sensitivity of the data sent across the communication link. Monitoring callers are exempted from this risk.",
		FalsePositives: "Technical assets which do not process requests regarding functionality or data linked to end-users (customers) " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        306,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks(input *model.ParsedModel) []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technology == types.LoadBalancer ||
			technicalAsset.Technology == types.ReverseProxy || technicalAsset.Technology == types.ServiceRegistry || technicalAsset.Technology == types.WAF || technicalAsset.Technology == types.IDS || technicalAsset.Technology == types.IPS {
			continue
		}
		if technicalAsset.HighestConfidentiality(input) >= types.Confidential ||
			technicalAsset.HighestIntegrity(input) >= types.Critical ||
			technicalAsset.HighestAvailability(input) >= types.Critical ||
			technicalAsset.MultiTenant {
			// check each incoming data flow
			commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, commLink := range commLinks {
				caller := input.TechnicalAssets[commLink.SourceId]
				if caller.Technology.IsUnprotectedCommunicationsTolerated() || caller.Type == types.Datastore {
					continue
				}
				highRisk := commLink.HighestConfidentiality(input) == types.StrictlyConfidential ||
					commLink.HighestIntegrity(input) == types.MissionCritical
				lowRisk := commLink.HighestConfidentiality(input) <= types.Internal &&
					commLink.HighestIntegrity(input) == types.Operational
				impact := types.MediumImpact
				if highRisk {
					impact = types.HighImpact
				} else if lowRisk {
					impact = types.LowImpact
				}
				if commLink.Authentication == types.NoneAuthentication && !commLink.Protocol.IsProcessLocal() {
					risks = append(risks, CreateRisk(input, technicalAsset, commLink, commLink, "", impact, types.Likely, false, Category()))
				}
			}
		}
	}
	return risks
}

func CreateRisk(input *model.ParsedModel, technicalAsset model.TechnicalAsset, incomingAccess, incomingAccessOrigin model.CommunicationLink, hopBetween string,
	impact types.RiskExploitationImpact, likelihood types.RiskExploitationLikelihood, twoFactor bool, category model.RiskCategory) model.Risk {
	factorString := ""
	if twoFactor {
		factorString = "Two-Factor "
	}
	if len(hopBetween) > 0 {
		hopBetween = "forwarded via <b>" + hopBetween + "</b> "
	}
	risk := model.Risk{
		Category:               category,
		Severity:               model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Missing " + factorString + "Authentication</b> covering communication link <b>" + incomingAccess.Title + "</b> " +
			"from <b>" + input.TechnicalAssets[incomingAccessOrigin.SourceId].Title + "</b> " + hopBetween +
			"to <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingAccess.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + incomingAccess.Id + "@" + input.TechnicalAssets[incomingAccess.SourceId].Id + "@" + technicalAsset.Id
	return risk
}
