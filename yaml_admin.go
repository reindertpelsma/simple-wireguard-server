package main

import (
	"encoding/json"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

type yamlConfigResponse struct {
	Enabled   bool   `json:"enabled"`
	Custom    string `json:"custom"`
	Effective string `json:"effective"`
	Generated string `json:"generated"`
}

func setConfigValue(key, value string) error {
	return gdb.Where(GlobalConfig{Key: key}).
		Assign(GlobalConfig{Value: value}).
		FirstOrCreate(&GlobalConfig{}).Error
}

func handleGetYAMLConfig(w http.ResponseWriter, r *http.Request) {
	effective, _ := os.ReadFile(resolvePath("uwg_canonical.yaml"))
	generated := generatedYAMLPreview()
	resp := yamlConfigResponse{
		Enabled:   getConfig("custom_yaml_enabled") == "true",
		Custom:    getConfig("custom_yaml"),
		Effective: string(effective),
		Generated: generated,
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
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
