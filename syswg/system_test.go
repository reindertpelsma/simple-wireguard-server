// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build system_test

package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestSystemInterfaceCreation(t *testing.T) {
	m, err := NewManager()
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer m.Cleanup()

	// Verify interface exists
	link, err := netlink.LinkByName(*ifName)
	if err != nil {
		t.Fatalf("interface %s not found: %v", *ifName, err)
	}

	if link.Type() != "wireguard" {
		t.Errorf("expected type wireguard, got %s", link.Type())
	}
}

func TestSystemAPIStatus(t *testing.T) {
	m, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Cleanup()

	req := httptest.NewRequest("GET", "/v1/status", nil)
	w := httptest.NewRecorder()
	m.handleStatus(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var status map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to parse status JSON: %v", err)
	}

	if status["name"] != *ifName {
		t.Errorf("expected interface name %s, got %v", *ifName, status["name"])
	}
}

func TestSystemIPAssignment(t *testing.T) {
	m, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Cleanup()

	// Mock manual address assignment
	link, _ := netlink.LinkByName(*ifName)
	addr, _ := netlink.ParseAddr("10.99.99.1/24")
	netlink.AddrAdd(link, addr)

	req := httptest.NewRequest("GET", "/v1/interface_ips", nil)
	w := httptest.NewRecorder()
	m.handleInterfaceIPs(w, req)

	var ips []string
	json.Unmarshal(w.Body.Bytes(), &ips)
	
	found := false
	for _, ip := range ips {
		if ip == "10.99.99.1/24" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected IP 10.99.99.1/24 in list, got %v", ips)
	}
}
