package detectors

import "github.com/alfagen/pii-service/internal/pii"

// All returns every built-in detector.
func All() []pii.Detector {
	return []pii.Detector{
		// Card holder is more specific than a generic full name for an
		// identical span, so register it first for the stable overlap tie-break.
		NewCardHolderDetector(),
		NewFullNameDetector(),
		NewDateDetector(),
		NewPlaceOfBirthDetector(),
		NewPassportDetector(),
		NewCitizenshipDetector(),
		NewDriverLicenseDetector(),
		NewAddressDetector(),
		NewEmailDetector(),
		NewPhoneDetector(),
		NewINNDetector(),
		NewCardNumberDetector(),
		NewCVVDetector(),
		NewCardPINDetector(),
	}
}
