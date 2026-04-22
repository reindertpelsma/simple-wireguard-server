package main

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type yamlConfigResponse struct {
	Enabled   bool   `json:"enabled"`
	Custom    string `json:"custom"`
	Effective string `json:"effective"`
	Generated string `json:"generated"`
}

var yamlSecretLine = regexp.MustCompile(`^(\s*(?:private_key|preshared_key|server_privkey|token|password)\s*:\s*).*$`)

func setConfigValue(key, value string) error {
	return gdb.Where(GlobalConfig{Key: key}).
		Assign(GlobalConfig{Value: value}).
		FirstOrCreate(&GlobalConfig{}).Error
}

func handleGetYAMLConfig(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	effective, _ := os.ReadFile(resolvePath("uwg_canonical.yaml"))
	generated := generatedYAMLPreview()
	resp := yamlConfigResponse{
		Enabled:   getConfig("custom_yaml_enabled") == "true",
		Generated: redactYAMLSecrets(generated),
	}
	if userHasActiveSudo(user, time.Now()) && r.URL.Query().Get("sensitive") == "1" {
		resp.Custom = getConfig("custom_yaml")
		if r.URL.Query().Get("include_effective") == "1" {
			resp.Effective = redactYAMLSecrets(string(effective))
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleSaveYAMLConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool   `json:"enabled"`
		Custom  string `json:"custom"`
		YAML    string `json:"yaml"`
	}
	if !decodeJSONRequest(w, r, &req, largeJSONBodyLimit) {
		return
	}
	custom := req.Custom
	if custom == "" && req.YAML != "" {
		custom = req.YAML
	}
	if req.Enabled {
		var parsed map[string]interface{}
		if err := yaml.Unmarshal([]byte(custom), &parsed); err != nil || len(parsed) == 0 {
			if err == nil {
				http.Error(w, "Custom YAML must be a non-empty mapping", http.StatusBadRequest)
			} else {
				http.Error(w, "Invalid custom YAML: "+err.Error(), http.StatusBadRequest)
			}
			return
		}
	}

	if err := setConfigValue("custom_yaml_enabled", boolString(req.Enabled)); err != nil {
		http.Error(w, "Failed to save YAML toggle", http.StatusInternalServerError)
		return
	}
	if err := setConfigValue("custom_yaml", custom); err != nil {
		http.Error(w, "Failed to save custom YAML", http.StatusInternalServerError)
		return
	}
	generateCanonicalYAML()
	w.WriteHeader(http.StatusNoContent)
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func generatedYAMLPreview() string {
	return string(buildCanonicalYAMLBytes(false))
}

func redactYAMLSecrets(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		if matches := yamlSecretLine.FindStringSubmatch(line); len(matches) == 2 {
			lines[i] = matches[1] + "<redacted>"
		}
	}
	return strings.Join(lines, "\n")
}
