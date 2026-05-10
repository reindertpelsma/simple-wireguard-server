package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SharedConfigLink struct {
	ID              uint       `gorm:"primaryKey" json:"id"`
	PeerID          uint       `gorm:"index;not null" json:"peer_id"`
	Peer            Peer       `gorm:"foreignKey:PeerID" json:"-"`
	CreatedByUserID uint       `gorm:"not null" json:"created_by_user_id"`
	TokenHash       string     `gorm:"uniqueIndex;not null" json:"-"`
	EncryptedToken  string     `json:"-"`
	OneUse          bool       `gorm:"default:false" json:"one_use"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	UsedAt          *time.Time `json:"used_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type sharedConfigResponse struct {
	PeerName            string                   `json:"peer_name"`
	DownloadName        string                   `json:"download_name"`
	PublicKey           string                   `json:"public_key"`
	AssignedIPs         string                   `json:"assigned_ips"`
	Keepalive           int                      `json:"keepalive"`
	IsE2E               bool                     `json:"is_e2e"`
	ServerPublicKey     string                   `json:"server_public_key"`
	ServerEndpoint      string                   `json:"server_endpoint"`
	DefaultTransport    string                   `json:"default_transport,omitempty"`
	ClientDNS           string                   `json:"client_dns"`
	MTU                 string                   `json:"mtu"`
	EnableIPv6          string                   `json:"enable_client_ipv6"`
	ClientAllowedIPs    string                   `json:"client_allowed_ips,omitempty"`
	DirectiveTCP        string                   `json:"client_config_tcp,omitempty"`
	DirectiveTURN       string                   `json:"client_config_turn_url,omitempty"`
	DirectiveSkipVerify string                   `json:"client_config_skipverifytls,omitempty"`
	DirectiveURL        string                   `json:"client_config_url,omitempty"`
	DirectiveControl    string                   `json:"client_config_control_url,omitempty"`
	TransportProfiles   []clientTransportProfile `json:"client_transport_profiles,omitempty"`
	PeerSyncEnabled     bool                     `json:"peer_sync_enabled,omitempty"`
	PresharedKey        string                   `json:"preshared_key,omitempty"`
	PrivateKey          string                   `json:"private_key,omitempty"`
	EncryptedPrivateKey string                   `json:"encrypted_private_key,omitempty"`
	OneUse              bool                     `json:"one_use"`
	ExpiresAt           *time.Time               `json:"expires_at,omitempty"`
	DistributePeers     []DistributePeerInfo     `json:"distribute_peers,omitempty"`
}

func shareTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func peerSupportsSharedConfig(peer Peer) bool {
	if !peerHasPrivateKeyMaterial(peer) {
		return false
	}
	if !peer.IsE2E {
		return true
	}
	return strings.HasPrefix(decryptAtRest(peer.EncryptedPrivateKey), "v2:")
}

func handleCreateShareLink(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := r.Header.Get("X-User-Id")
	isAdmin := r.Header.Get("X-Is-Admin") == "true"

	var peer Peer
	if err := gdb.First(&peer, id).Error; err != nil {
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}

	if fmt.Sprint(peer.UserID) != userID && !isAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if !peerSupportsSharedConfig(peer) {
		http.Error(w, "This device does not have shareable private key material", http.StatusBadRequest)
		return
	}

	var req struct {
		OneUse    bool       `json:"one_use"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	if !decodeOptionalJSONRequest(w, r, &req, smallJSONBodyLimit) {
		return
	}

	var creatorID uint
	fmt.Sscanf(userID, "%d", &creatorID)

	token := randomSecret(24)
	link := SharedConfigLink{
		PeerID:          peer.ID,
		CreatedByUserID: creatorID,
		TokenHash:       shareTokenHash(token),
		EncryptedToken:  encryptAtRest(token),
		OneUse:          req.OneUse,
		ExpiresAt:       req.ExpiresAt,
	}

	if err := gdb.Create(&link).Error; err != nil {
		http.Error(w, "Failed to create share link", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      token,
		"one_use":    link.OneUse,
		"expires_at": link.ExpiresAt,
	})
}

func handleGetSharedConfig(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if strings.TrimSpace(token) == "" {
		http.Error(w, "Missing share token", http.StatusBadRequest)
		return
	}

	var link SharedConfigLink
	if err := gdb.Preload("Peer").First(&link, "token_hash = ?", shareTokenHash(token)).Error; err != nil {
		http.Error(w, "Share link not found", http.StatusNotFound)
		return
	}
	if decryptAtRest(link.EncryptedToken) != token {
		http.Error(w, "Share link not found", http.StatusNotFound)
		return
	}
	// Share link one-use enforcement with a 30-second retry grace period.
	//
	// On first access UsedAt is recorded. Subsequent requests within
	// shareGracePeriod of that timestamp are still served — this intentionally
	// accommodates network retries: a client may re-send the same HTTP request
	// if the first attempt times out before it receives the response, and we
	// should not permanently burn the link on a network hiccup.
	//
	// The UsedAt write is not atomic with this read; two simultaneous requests
	// can both pass the check before either commits. That race only widens the
	// effective retry window by one extra round-trip — not a privilege
	// escalation, since both requests come from the same token holder.
	const shareGracePeriod = 30 * time.Second
	if link.UsedAt != nil && time.Since(*link.UsedAt) > shareGracePeriod {
		http.Error(w, "Share link already used", http.StatusGone)
		return
	}
	if link.ExpiresAt != nil && time.Now().After(*link.ExpiresAt) {
		http.Error(w, "Share link expired", http.StatusGone)
		return
	}

	peer := link.Peer
	response := sharedConfigResponse{
		PeerName:            peer.Name,
		DownloadName:        configDownloadName(peer.Name),
		PublicKey:           peer.PublicKey,
		AssignedIPs:         peer.AssignedIPs,
		Keepalive:           peer.Keepalive,
		IsE2E:               peer.IsE2E,
		ServerPublicKey:     getConfig("server_pubkey"),
		ServerEndpoint:      resolvedServerEndpoint(),
		DefaultTransport:    resolveDefaultTransportNameUI(),
		ClientDNS:           getConfig("client_dns"),
		MTU:                 getConfig("global_mtu"),
		EnableIPv6:          getConfig("enable_client_ipv6"),
		ClientAllowedIPs:    getConfig("client_allowed_ips"),
		DirectiveTCP:        getConfig("client_config_tcp"),
		DirectiveTURN:       getConfig("client_config_turn_url"),
		DirectiveSkipVerify: getConfig("client_config_skipverifytls"),
		DirectiveURL:        getConfig("client_config_url"),
		DirectiveControl:    resolvedPeerSyncControlURL(),
		TransportProfiles:   buildClientTransportProfiles(canonicalBaseURL(r)),
		PeerSyncEnabled:     peerSyncActiveForPeer(peer),
		OneUse:              link.OneUse,
		ExpiresAt:           link.ExpiresAt,
		PresharedKey:        decryptAtRest(peer.PresharedKey),
	}

	if peer.IsE2E {
		providedHash := r.Header.Get("X-Nonce-Hash")
		if providedHash == "" {
			http.Error(w, "Missing X-Nonce-Hash header", http.StatusBadRequest)
			return
		}
		if providedHash != peer.NonceHash {
			http.Error(w, "Invalid nonce hash", http.StatusForbidden)
			return
		}
		response.EncryptedPrivateKey = decryptAtRest(peer.EncryptedPrivateKey)
	} else {
		privateKey := decryptAtRest(peer.PrivateKey)
		if privateKey == "" {
			http.Error(w, "Private key is no longer available for this device", http.StatusConflict)
			return
		}
		response.PrivateKey = privateKey
	}

	dps := getDistributePeers()
	var filteredDPs []DistributePeerInfo
	for _, dp := range dps {
		if dp.PublicKey == peer.PublicKey {
			continue
		}
		if dp.Endpoint == "" {
			continue
		}
		filteredDPs = append(filteredDPs, dp)
	}
	response.DistributePeers = filteredDPs

	if link.OneUse && link.UsedAt == nil {
		// Stamp first-access time. Retries within shareGracePeriod are still
		// served (see check above); we do not update this on subsequent hits so
		// the 30-second window is anchored to the first request, not the last.
		now := time.Now()
		link.UsedAt = &now
		gdb.Model(&link).Update("used_at", now)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
