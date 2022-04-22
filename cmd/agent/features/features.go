package features

type FeatureID string

const (
	UpgradeToMultiMetrics FeatureID = "upgrade-to-multi-metrics"
)

// Features Structure for describing features published by StackState
type Features interface {
	FeatureEnabled(feature FeatureID) bool
}

// Impl Implementation
type Impl struct {
	features map[FeatureID]bool
}

// AllFeatures supported
type AllFeatures struct{}

// All features supported
func All() AllFeatures {
	return AllFeatures{}
}

// FeatureEnabled check
func (f AllFeatures) FeatureEnabled(_ FeatureID) bool {
	return true
}

// Empty features supported
func Empty() Impl {
	return Impl{
		features: make(map[FeatureID]bool),
	}
}

// Make features based on map
func Make(features map[FeatureID]bool) Impl {
	return Impl{
		features: features,
	}
}

// FeatureEnabled check
func (f Impl) FeatureEnabled(feature FeatureID) bool {
	if supported, ok := f.features[feature]; ok {
		return supported
	}
	return false
}
