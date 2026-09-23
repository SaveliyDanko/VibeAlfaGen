// Package pii defines the core domain types for personal data detection:
// PIIType, Finding, Detector and the Registry that coordinates detectors.
//
// Indexing convention: all Start/End offsets in Finding are BYTE offsets into
// the original UTF-8 string. This is deliberate: byte offsets allow safe
// slicing of the original string (s[start:end]) without re-encoding, and the
// transformer applies findings right-to-left so earlier offsets stay valid.
// Rune offsets are NOT used; callers that need rune positions must convert.
package pii

// PIIType identifies a category of personal data.
type PIIType string

// The 17 supported PII categories.
const (
	TypeFullName          PIIType = "full_name"
	TypeDateOfBirth       PIIType = "date_of_birth"
	TypePlaceOfBirth      PIIType = "place_of_birth"
	TypePassportNumber    PIIType = "passport_number"
	TypeCitizenship       PIIType = "citizenship"
	TypePassportIssuer    PIIType = "passport_issuer"
	TypePassportDivision  PIIType = "passport_division_code"
	TypePassportIssueDate PIIType = "passport_issue_date"
	TypeDriverLicense     PIIType = "driver_license"
	TypeAddress           PIIType = "address"
	TypeEmail             PIIType = "email"
	TypePhone             PIIType = "phone"
	TypeINN               PIIType = "inn"
	TypeCardNumber        PIIType = "card_number"
	TypeCVV               PIIType = "cvv"
	TypeCardPIN           PIIType = "card_pin"
	TypeCardHolder        PIIType = "card_holder"
)

// AllTypes lists every supported PII type.
var AllTypes = []PIIType{
	TypeFullName,
	TypeDateOfBirth,
	TypePlaceOfBirth,
	TypePassportNumber,
	TypeCitizenship,
	TypePassportIssuer,
	TypePassportDivision,
	TypePassportIssueDate,
	TypeDriverLicense,
	TypeAddress,
	TypeEmail,
	TypePhone,
	TypeINN,
	TypeCardNumber,
	TypeCVV,
	TypeCardPIN,
	TypeCardHolder,
}

// Confidence expresses how sure a detector is about a finding.
type Confidence float64

const (
	ConfidenceLow    Confidence = 0.4
	ConfidenceMedium Confidence = 0.7
	ConfidenceHigh   Confidence = 0.95
)

// Finding is a single detected span of personal data. Start and End are BYTE
// offsets into the original UTF-8 string (see package doc). The Value field is
// populated by the detector for internal use (masking) but MUST never be
// logged, traced or used as a metric label.
type Finding struct {
	Type       PIIType
	Start      int
	End        int
	Confidence Confidence
	Detector   string
	Value      string
	// Evidence contains bounded, non-sensitive recognizer signals. It is not
	// persisted by the engine and must not contain text.
	Evidence Evidence `json:",omitempty"`
}

type Evidence uint8

const (
	EvidenceLabel Evidence = 1 << iota
	EvidenceTrap
	// EvidenceRequiresAnchor marks a name whose surname is not in the lexical
	// grammar. It must have independent personal context even in strict mode.
	EvidenceRequiresAnchor
)

// CandidateDetector is optional. Candidates are unresolved and never imply
// permission to mask; the contextual resolver and policy decide that.
type CandidateDetector interface {
	Candidates(string) []Finding
}

// Detector finds personal data in a string. Detectors are pure: they only
// locate data and return findings; they never modify the input text.
type Detector interface {
	// Type returns the PII category this detector produces.
	Type() PIIType
	// Detect returns findings for the given input. The returned findings must
	// have valid byte offsets (Start < End, within len(input)).
	Detect(input string) []Finding
}

// SupportedTypes returns every category a detector may emit. A detector may
// classify several related categories (for example birth and issue dates).
func SupportedTypes(d Detector) []PIIType {
	if multi, ok := d.(interface{ Types() []PIIType }); ok {
		return multi.Types()
	}
	return []PIIType{d.Type()}
}
