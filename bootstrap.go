package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type bootstrapInfo struct {
	FirstStart    bool
	AdminPassword string
}

var bootstrapState bootstrapInfo

func flagWasProvided(name string) bool {
	provided := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			provided = true
		}
	})
	return provided
}

func randomSecret(byteCount int) string {
	buf := make([]byte, byteCount)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func ensureInitialAdminUser() {
	var count int64
	gdb.Model(&User{}).Count(&count)
	if count != 0 {
		return
	}

	password := randomSecret(18)
	hash, err := hashPassword(password)
	if err != nil {
		log.Fatalf("Failed to hash bootstrap admin password: %v", err)
	}

	admin := User{
		Username:     "admin",
		PasswordHash: hash,
		IsAdmin:      true,
		MaxConfigs:   999,
	}
	if err := gdb.Create(&admin).Error; err != nil {
		log.Fatalf("Failed to create bootstrap admin: %v", err)
	}

	bootstrapState = bootstrapInfo{
		FirstStart:    true,
		AdminPassword: password,
	}

	log.Printf("First startup detected.")
	log.Printf("Bootstrap admin credentials: username=admin password=%s", password)
}

func shouldGenerateBootstrapConfig() bool {
	if bootstrapState.FirstStart && !flagWasProvided("generate-config") {
		return true
	}
	return *generateConfig
}

func maybeGenerateBootstrapConfig() {
	if !shouldGenerateBootstrapConfig() {
		return
	}
	if err := generateBootstrapPeer(); err != nil {
		log.Printf("Failed to generate bootstrap config: %v", err)
	}
}

func generateBootstrapPeer() error {
	var admin User
	if err := gdb.First(&admin, "username = ? AND is_admin = ?", "admin", true).Error; err != nil {
		return err
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	assignedIPs, err := allocateIP()
	if err != nil {
		return err
	}

	pskBytes := make([]byte, 32)
	if _, err := rand.Read(pskBytes); err != nil {
		return err
	}
	presharedKey := base64.StdEncoding.EncodeToString(pskBytes)

	peer := Peer{
		UserID:         admin.ID,
		Name:           fmt.Sprintf("Bootstrap Device %s", time.Now().UTC().Format("2006-01-02 15:04 UTC")),
		AssignedIPs:    assignedIPs,
		PublicKey:      privateKey.PublicKey().String(),
		PresharedKey:   encryptAtRest(presharedKey),
		Enabled:        true,
		Keepalive:      0,
		IsManualKey:    getConfig("e2e_encryption_enabled") == "true",
		IsE2E:          false,
		StaticEndpoint: "",
	}

	if !peer.IsManualKey {
		peer.PrivateKey = encryptAtRest(privateKey.String())
	}

	if err := gdb.Create(&peer).Error; err != nil {
		return err
	}

	log.Printf("Generated bootstrap peer %q for the admin account.", peer.Name)
	log.Printf("Bootstrap WireGuard config (%s):\n%s", configDownloadName(peer.Name), buildClientConfigText(peer, privateKey.String(), presharedKey, true))
	if peer.IsManualKey {
		log.Printf("Private key retention is disabled because end-to-end storage is enabled. Keep the printed bootstrap config safe.")
	}
	return nil
}
