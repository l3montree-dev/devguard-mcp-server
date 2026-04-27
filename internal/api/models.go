package api

type HealthResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type OrgResponse struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
}

type ProjectResponse struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
}

type AssetResponse struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
}

type AssetVersionResponse struct {
	Name          string `json:"name"`
	DefaultBranch bool   `json:"defaultBranch"`
}

type PagedResponse[T any] struct {
	Data  []T   `json:"data"`
	Total int64 `json:"total"`
}

type CVEResponse struct {
	CVE              string   `json:"cve"`
	Description      string   `json:"description"`
	CVSS             float32  `json:"cvss"`
	Vector           string   `json:"vector"`
	EPSS             *float64 `json:"epss"`
	Percentile       *float32 `json:"percentile"`
	DatePublished    string   `json:"datePublished"`
	DateLastModified string   `json:"dateLastModified"`
}

type DependencyVulnResponse struct {
	ID                           string      `json:"id"`
	State                        string      `json:"state"`
	Message                      *string     `json:"message"`
	CVEID                        string      `json:"cveID"`
	CVE                          CVEResponse `json:"cve"`
	ComponentPurl                string      `json:"componentPurl"`
	DirectDependencyFixedVersion *string     `json:"directDependencyFixedVersion"`
	VulnerabilityPath            []string    `json:"vulnerabilityPath"`
	RawRiskAssessment            *float64    `json:"rawRiskAssessment"`
	Effort                       *int        `json:"effort"`
	Priority                     *int        `json:"priority"`
	LastDetected                 string      `json:"lastDetected"`
	TicketID                     *string     `json:"ticketId"`
	TicketURL                    *string     `json:"ticketUrl"`
}

type ExploitResponse struct {
	ID          string `json:"id"`
	Author      string `json:"author"`
	Verified    bool   `json:"verified"`
	SourceURL   string `json:"sourceURL"`
	Description string `json:"description"`
}

type DetailedCVEResponse struct {
	CVE                   string            `json:"cve"`
	Description           string            `json:"description"`
	CVSS                  float32           `json:"cvss"`
	Vector                string            `json:"vector"`
	EPSS                  *float64          `json:"epss"`
	Percentile            *float32          `json:"percentile"`
	DatePublished         string            `json:"datePublished"`
	DateLastModified      string            `json:"dateLastModified"`
	CISAExploitAdd        *string           `json:"cisaExploitAdd"`
	CISARequiredAction    string            `json:"cisaRequiredAction"`
	CISAVulnerabilityName string            `json:"cisaVulnerabilityName"`
	Exploits              []ExploitResponse `json:"exploits"`
}

type VulnEventResponse struct {
	Type          string `json:"type"`
	Justification string `json:"justification"`
	UserID        string `json:"userId"`
	CreatedAt     string `json:"createdAt"`
}

type DetailedDependencyVulnResponse struct {
	ID                           string              `json:"id"`
	State                        string              `json:"state"`
	CVEID                        string              `json:"cveID"`
	CVE                          DetailedCVEResponse `json:"cve"`
	ComponentPurl                string              `json:"componentPurl"`
	ComponentFixedVersion        *string             `json:"componentFixedVersion"`
	DirectDependencyFixedVersion *string             `json:"directDependencyFixedVersion"`
	VulnerabilityPath            []string            `json:"vulnerabilityPath"`
	RawRiskAssessment            *float64            `json:"rawRiskAssessment"`
	Events                       []VulnEventResponse `json:"events"`
}

type VulnHintResponse struct {
	AmountOpen              int `json:"amountOpen"`
	AmountFixed             int `json:"amountFixed"`
	AmountAccepted          int `json:"amountAccepted"`
	AmountFalsePositive     int `json:"amountFalsePositive"`
	AmountMarkedForTransfer int `json:"amountMarkedForTransfer"`
}

type FirstPartyVulnResponse struct {
	ID              string  `json:"id"`
	State           string  `json:"state"`
	Message         *string `json:"message"`
	RuleID          string  `json:"ruleId"`
	RuleName        string  `json:"ruleName"`
	RuleDescription string  `json:"ruleDescription"`
	URI             string  `json:"uri"`
	Author          string  `json:"author"`
	Commit          string  `json:"commit"`
	Date            string  `json:"date"`
	LastDetected    string  `json:"lastDetected"`
}
