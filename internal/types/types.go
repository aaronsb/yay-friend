package types

import (
	"context"
	"time"
)

// SecurityEntropy represents the security assessment entropy level
type SecurityEntropy int

const (
	EntropyMinimal SecurityEntropy = iota  // Very predictable, low risk
	EntropyLow                            // Some uncertainty, minor risk
	EntropyModerate                       // Moderate uncertainty, concerning
	EntropyHigh                           // High uncertainty, suspicious  
	EntropyCritical                       // Maximum uncertainty, dangerous
)

func (s SecurityEntropy) String() string {
	switch s {
	case EntropyMinimal:
		return "MINIMAL"
	case EntropyLow:
		return "LOW"  
	case EntropyModerate:
		return "MODERATE"
	case EntropyHigh:
		return "HIGH"
	case EntropyCritical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

// Legacy aliases for backward compatibility
type SecurityLevel = SecurityEntropy
const (
	SecuritySafe     = EntropyMinimal
	SecurityLow      = EntropyLow
	SecurityMedium   = EntropyModerate
	SecurityHigh     = EntropyHigh
	SecurityCritical = EntropyCritical
)

// MarshalYAML implements yaml.Marshaler interface
func (s SecurityLevel) MarshalYAML() (interface{}, error) {
	return int(s), nil
}

// UnmarshalYAML implements yaml.Unmarshaler interface
func (s *SecurityLevel) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var level int
	if err := unmarshal(&level); err != nil {
		return err
	}
	*s = SecurityLevel(level)
	return nil
}

// SecurityFinding represents a specific security issue found
type SecurityFinding struct {
	Type         string          `json:"type"`
	Entropy      SecurityEntropy `json:"entropy"`      // How much uncertainty this adds
	Severity     SecurityLevel   `json:"severity"`     // Legacy field for compatibility
	Description  string          `json:"description"`
	LineNumber   int             `json:"line_number,omitempty"`
	Context      string          `json:"context,omitempty"`
	Suggestion   string          `json:"suggestion,omitempty"`
	EntropyNotes string          `json:"entropy_notes,omitempty"` // Why this contributes to entropy
}

// SecurityAnalysis represents the complete security analysis of a PKGBUILD
type SecurityAnalysis struct {
	PackageName         string            `json:"package_name"`
	OverallEntropy      SecurityEntropy   `json:"overall_entropy"`    // Primary entropy assessment
	OverallLevel        SecurityLevel     `json:"overall_level"`      // Legacy compatibility
	Findings            []SecurityFinding `json:"findings"`
	Summary             string            `json:"summary"`
	Recommendation      string            `json:"recommendation"`
	AnalyzedAt          time.Time         `json:"analyzed_at"`
	Provider            string            `json:"provider"`
	EntropyFactors      []string          `json:"entropy_factors,omitempty"`      // What contributed to entropy
	PredictabilityScore float64           `json:"predictability_score,omitempty"` // 0.0 (chaotic) to 1.0 (predictable)
	EducationalSummary  string            `json:"educational_summary,omitempty"`  // Educational context for users
	SecurityLessons     []string          `json:"security_lessons,omitempty"`     // Key takeaways for learning
}

// PackageInfo represents basic package information
type PackageInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Maintainer  string `json:"maintainer"`
	PKGBUILD    string `json:"pkgbuild"`
	CommitHash  string `json:"commit_hash"` // AUR git commit hash for caching
	// AUR page context
	AURPageURL       string   `json:"aur_page_url,omitempty"`
	LastUpdated      string   `json:"last_updated,omitempty"`
	FirstSubmitted   string   `json:"first_submitted,omitempty"`
	Votes            int      `json:"votes,omitempty"`
	Popularity       float64  `json:"popularity,omitempty"`
	Comments         []string `json:"comments,omitempty"`
	Dependencies     []string `json:"dependencies,omitempty"`
	MakeDepends      []string `json:"make_depends,omitempty"`
	OptDepends       []string `json:"opt_depends,omitempty"`
}

// AIProvider interface for different AI backends
type AIProvider interface {
	Name() string
	Authenticate(ctx context.Context) error
	IsAuthenticated() bool
	AnalyzePKGBUILD(ctx context.Context, pkgInfo PackageInfo) (*SecurityAnalysis, error)
	GetCapabilities() ProviderCapabilities
}

// ProviderCapabilities describes what a provider can do
type ProviderCapabilities struct {
	SupportsCodeAnalysis bool
	SupportsExplanations bool
	RateLimitPerMinute   int
	MaxAnalysisSize      int // in bytes
}

// Config represents the application configuration
type Config struct {
	DefaultProvider string            `yaml:"default_provider"`
	Providers       map[string]string `yaml:"providers"` // provider_name -> config_path
	SecurityThresholds struct {
		BlockLevel    SecurityLevel `yaml:"block_level"`
		WarnLevel     SecurityLevel `yaml:"warn_level"`
		AutoProceed   bool          `yaml:"auto_proceed_safe"`
	} `yaml:"security_thresholds"`
	Cache struct {
		Enabled      bool `yaml:"enabled"`
		MaxAgeDays   int  `yaml:"max_age_days"`
		MaxSizeMB    int  `yaml:"max_size_mb"`
		Compress     bool `yaml:"compress"`
	} `yaml:"cache"`
	Prompts struct {
		SecurityAnalysis string `yaml:"security_analysis"`
	} `yaml:"prompts"`
	UI struct {
		ShowDetails   bool `yaml:"show_details"`
		UseColors     bool `yaml:"use_colors"`
		VerboseOutput bool `yaml:"verbose_output"`
	} `yaml:"ui"`
	Yay struct {
		Path  string   `yaml:"path"`
		Flags []string `yaml:"default_flags"`
	} `yaml:"yay"`
}

// YayOperation represents the operation to perform with yay
type YayOperation struct {
	Command   string   `json:"command"`
	Packages  []string `json:"packages"`
	Flags     []string `json:"flags"`
	Operation string   `json:"operation"` // install, upgrade, remove, etc.
}