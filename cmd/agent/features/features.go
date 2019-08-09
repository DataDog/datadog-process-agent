package features

// Features Structure for describing features published by StackState
type Features interface {
	FeatureEnabled(feature string) bool
}

// Impl Implementation
type Impl struct {
	features map[string]bool
}

// AllFeatures supported
type AllFeatures struct{}

// All features supported
func All() AllFeatures {
	return AllFeatures{}
}

// FeatureEnabled check
func (f AllFeatures) FeatureEnabled(feature string) bool {
	return true
}

// Empty features supported
func Empty() Impl {
	return Impl{
		features: make(map[string]bool),
	}
}

// Make features based on map
func Make(features map[string]bool) Impl {
	return Impl{
		features: features,
	}
}

// FeatureEnabled check
func (f Impl) FeatureEnabled(feature string) bool {
	if supported, ok := f.features[feature]; ok {
		return supported
	}
	return false
}
