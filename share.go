package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	PeerName            string               `json:"peer_name"`
	DownloadName        string               `json:"download_name"`
	PublicKey           string               `json:"public_key"`
	AssignedIPs         string               `json:"assigned_ips"`
	Keepalive           int                  `json:"keepalive"`
	IsE2E               bool                 `json:"is_e2e"`
	ServerPublicKey     string               `json:"server_public_key"`
	ServerEndpoint      string               `json:"server_endpoint"`
	DefaultTransport    string               `json:"default_transport,omitempty"`
	ClientDNS           string               `json:"client_dns"`
	MTU                 string               `json:"mtu"`
	EnableIPv6          string               `json:"enable_client_ipv6"`
	ClientAllowedIPs    string               `json:"client_allowed_ips,omitempty"`
	DirectiveTCP        string               `json:"client_config_tcp,omitempty"`
	DirectiveTURN       string               `json:"client_config_turn_url,omitempty"`
	DirectiveSkipVerify string               `json:"client_config_skipverifytls,omitempty"`
	DirectiveURL        string               `json:"client_config_url,omitempty"`
	DirectiveControl    string               `json:"client_config_control_url,omitempty"`
	PeerSyncEnabled     bool                 `json:"peer_sync_enabled,omitempty"`
	PresharedKey        string               `json:"preshared_key,omitempty"`
	PrivateKey          string               `json:"private_key,omitempty"`
	EncryptedPrivateKey string               `json:"encrypted_private_key,omitempty"`
	OneUse              bool                 `json:"one_use"`
	ExpiresAt           *time.Time           `json:"expires_at,omitempty"`
	DistributePeers     []DistributePeerInfo `json:"distribute_peers,omitempty"`
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
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "Invalid request", http.StatusBadRequest)
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
	if link.UsedAt != nil {
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

	if link.OneUse {
		now := time.Now()
		link.UsedAt = &now
		gdb.Model(&link).Update("used_at", now)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
