package wrong_trust_boundary_content

import (
	"github.com/threagile/threagile/model"
	"github.com/threagile/threagile/pkg/security/types"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "wrong-trust-boundary-content",
		Title: "Wrong Trust Boundary Content",
		Description: "When a trust boundary of type " + types.NetworkPolicyNamespaceIsolation.String() + " contains " +
			"non-container assets it is likely to be a model failure.",
		Impact:                     "If this potential model error is not fixed, some risks might not be visible.",
		ASVS:                       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html",
		Action:                     "Model Consistency",
		Mitigation:                 "Try to model the correct types of trust boundaries and data assets.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   types.Architecture,
		STRIDE:                     types.ElevationOfPrivilege,
		DetectionLogic:             "Trust boundaries which should only contain containers, but have different assets inside.",
		RiskAssessment:             types.LowSeverity.String(),
		FalsePositives:             "Usually no false positives as this looks like an incomplete model.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, trustBoundary := range model.ParsedModelRoot.TrustBoundaries {
		if trustBoundary.Type == types.NetworkPolicyNamespaceIsolation {
			for _, techAssetID := range trustBoundary.TechnicalAssetsInside {
				techAsset := model.ParsedModelRoot.TechnicalAssets[techAssetID]
				if techAsset.Machine != types.Container && techAsset.Machine != types.Serverless {
					risks = append(risks, createRisk(techAsset))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Wrong Trust Boundary Content</b> (non-container asset inside container trust boundary) at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(types.Unlikely, types.LowImpact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           types.LowImpact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
