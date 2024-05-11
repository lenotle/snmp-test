package scraper

import (
	"context"
	"errors"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"log/slog"
	"net"
	"strings"
	"time"
)

type SNMPScraper interface {
	Connect() error
	Close() error
	SetOptions(...func(snmp *gosnmp.GoSNMP))
	Get([]string) (*gosnmp.SnmpPacket, error)
	WalkAll(string) ([]gosnmp.SnmpPDU, error)
}

var _ SNMPScraper = (*GoSNMPWrapper)(nil)

func NewGoSNMP(config *ClientConfig) (*GoSNMPWrapper, error) {
	gs := &gosnmp.GoSNMP{
		Timeout:            config.Timeout,
		Retries:            config.Retries,
		MaxRepetitions:     config.MaxRepetitions,
		ExponentialTimeout: false,
		AppOpts:            config.AppOpts,
		MaxOids:            config.MaxOIDs,
		Context:            config.Context,
	}

	ip := net.ParseIP(config.Target)
	if ip == nil {
		return nil, fmt.Errorf("invalid target: %s", config.Target)
	}
	gs.Target = ip.String()

	transport := "udp"
	if ip.To4() != nil {
		transport = "udp4"
	} else {
		transport = "udp6"
	}
	gs.Transport = transport
	gs.Port = config.Port

	switch config.Version {
	case Version3:
		gs.Version = gosnmp.Version3
	case Versionv2c:
		gs.Version = gosnmp.Version2c
	case Version1:
		gs.Version = gosnmp.Version1
	default:
		return nil, errors.New("invalid version, support (1/2c/3)")
	}

	if gs.Version < gosnmp.Version3 {
		if config.Community == "" {
			return nil, errors.New("community is null")
		}
		gs.Community = config.Community
	}

	if gs.Version == gosnmp.Version3 {
		gs.SecurityModel = gosnmp.UserSecurityModel
		usp := &gosnmp.UsmSecurityParameters{}
		gs.SecurityParameters = usp

		usp.UserName = config.SecName
		auth, priv := false, false

		// noAuthNoPriv|authNoPriv|authPriv
		switch strings.ToLower(config.SecLevel) {
		case "noauthnopriv":
			gs.MsgFlags = gosnmp.NoAuthNoPriv
		case "authnopriv":
			gs.MsgFlags = gosnmp.AuthNoPriv
			auth = true
		case "authpriv":
			gs.MsgFlags = gosnmp.AuthPriv
			auth = true
			priv = true
		default:
			return nil, errors.New("invalid secLevel, support (noAuthNoPriv|authNoPriv|authPriv)")
		}

		if auth {
			usp.AuthenticationPassphrase = config.AuthenticationPassphrase

			// ""|MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512
			switch strings.ToLower(config.AuthenticationProtocol) {
			case "":
				usp.AuthenticationProtocol = gosnmp.NoAuth
			case "md5":
				usp.AuthenticationProtocol = gosnmp.MD5
			case "sha":
				usp.AuthenticationProtocol = gosnmp.SHA
			case "sha-224":
				usp.AuthenticationProtocol = gosnmp.SHA224
			case "sha-256":
				usp.AuthenticationProtocol = gosnmp.SHA256
			case "sha-384":
				usp.AuthenticationProtocol = gosnmp.SHA384
			case "sha-512":
				usp.AuthenticationProtocol = gosnmp.SHA512
			default:
				return nil, errors.New("invalid authProtocol, support (\"\"|MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512)")
			}
		}

		if priv {
			usp.PrivacyPassphrase = config.PrivacyPassphrase

			// ""|DES|AES|AES192|AES256|AES256C
			switch strings.ToLower(config.PrivacyProtocol) {
			case "":
				usp.PrivacyProtocol = gosnmp.NoPriv
			case "des":
				usp.PrivacyProtocol = gosnmp.DES
			case "aes":
				usp.PrivacyProtocol = gosnmp.AES
			case "aes192":
				usp.PrivacyProtocol = gosnmp.AES192
			case "aes192c":
				usp.PrivacyProtocol = gosnmp.AES192C
			case "aes256":
				usp.PrivacyProtocol = gosnmp.AES256
			case "aes256c":
				usp.PrivacyProtocol = gosnmp.AES256C
			default:
				return nil, fmt.Errorf("invalid privProtocol, support (\"\"|des|aes|aes192|aes256|aes256c)")
			}
		}
	}

	return &GoSNMPWrapper{c: gs}, nil
}

// GoSNMPWrapper implement SNMPScraper
type GoSNMPWrapper struct {
	c *gosnmp.GoSNMP
}

func (gs *GoSNMPWrapper) Connect() error {
	st := time.Now()
	err := gs.c.Connect()
	if err != nil {
		if err == context.Canceled {
			return fmt.Errorf("snmp connect cancelled after %s connecting to target %s", time.Since(st), gs.c.Target)
		}
		return fmt.Errorf("error connecting to target %s: %s", gs.c.Target, err)
	}
	return nil
}

func (gs *GoSNMPWrapper) Close() error {
	return gs.c.Conn.Close()
}

func (gs *GoSNMPWrapper) SetOptions(fns ...func(snmp *gosnmp.GoSNMP)) {
	for _, fn := range fns {
		fn(gs.c)
	}
}

func (gs *GoSNMPWrapper) Get(oids []string) (results *gosnmp.SnmpPacket, err error) {
	slog.Debug("Getting OIDS", "oids", oids)
	st := time.Now()

	results, err = gs.c.Get(oids)
	if err != nil {
		if err == context.Canceled {
			err = fmt.Errorf("snmp connect cancelled after %s connecting to target %s", time.Since(st), gs.c.Target)
		} else {
			err = fmt.Errorf("error getting to target %s: %s", gs.c.Target, err)
		}
	}

	slog.Debug("Get of OIDs completed", "oids", oids, "duration", time.Since(st))
	return
}

func (gs *GoSNMPWrapper) WalkAll(oid string) (results []gosnmp.SnmpPDU, err error) {
	slog.Debug("Walking subtree", "oid", oid)
	st := time.Now()

	if gs.c.Version == gosnmp.Version1 {
		results, err = gs.c.WalkAll(oid)
	} else {
		results, err = gs.c.BulkWalkAll(oid)
	}
	if err != nil {
		if err == context.Canceled {
			err = fmt.Errorf("scrape canceled after %s walking target %s", time.Since(st), gs.c.Target)
		} else {
			err = fmt.Errorf("error walking target %s: %s", gs.c.Target, err)
		}
		return
	}

	slog.Debug("Walk of subtree completed", "oid", oid, "duration", time.Since(st))
	return
}
