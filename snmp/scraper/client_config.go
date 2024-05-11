package scraper

import (
	"context"
	"time"
)

const (
	Version1   = "snmpv1"
	Versionv2c = "snmpv2c"
	Version3   = "snmpv3"
)

type ClientConfig struct {
	Target  string
	Port    uint16
	Version string
	// version 1 && 2
	Community string

	// version 3
	// optional value: noAuthNoPriv|authNoPriv|authPriv
	SecLevel string
	SecName  string
	// optional value: ""|MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512
	AuthenticationProtocol   string
	AuthenticationPassphrase string
	// optional value: ""|DES|AES|AES192|AES256|AES256C
	PrivacyProtocol   string
	PrivacyPassphrase string

	Timeout        time.Duration
	Retries        int
	MaxRepetitions uint32

	AppOpts map[string]interface{}
	MaxOIDs int

	Context context.Context
}
