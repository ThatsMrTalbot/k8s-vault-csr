package token

import (
	"context"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/physical/inmem"
	"github.com/hashicorp/vault/vault"
)

func TestRenewer(t *testing.T) {
	// Set up vault

	logger := logging.NewVaultLogger(log.Trace)

	phys, err := inmem.NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
		return
	}

	core, err := vault.NewCore(&vault.CoreConfig{
		Physical: phys,
		LogicalBackends: map[string]logical.Factory{},
		DisableMlock: true,
	})

	if err != nil {
		t.Fatal("error initializing core: ", err)
		return
	}

	init, err := core.Initialize(context.Background(), &vault.InitParams{
		BarrierConfig: &vault.SealConfig{
			SecretShares:    1,
			SecretThreshold: 1,
		},
		RecoveryConfig: nil,
	})

	if err != nil {
		t.Fatal("error initializing core: ", err)
		return
	}

	if unsealed, err := core.Unseal(init.SecretShares[0]); err != nil {
		t.Fatal("error unsealing core: ", err)
		return
	} else if !unsealed {
		t.Fatal("vault shouldn't be sealed")
		return
	}

	ln, addr := http.TestServer(nil, core)
	defer ln.Close()

	clientConfig := api.DefaultConfig()
	clientConfig.Address = addr
	client, err := api.NewClient(clientConfig)

	if err != nil {
		t.Fatal("error initializing HTTP client: ", err)
		return
	}

	client.SetToken(init.RootToken)
	
	// Set token

	secret, err := client.Auth().Token().Create(&api.TokenCreateRequest{
		TTL: "3600",
	})

	if err != nil {
		t.Fatal("error creating child token: ", err)
		return
	}

	client.SetToken(secret.Auth.ClientToken)

	// Test case

	renewer := NewRenewer(client, nil)
	status, err := renewer.currentTokenStatus()

	if err != nil {
		t.Errorf("error getting token status: %s", err)
	}

	if !status.HasToken {
		t.Error("no token")
	}
	
	if status.Expired {
		t.Error("token is expired")
	}

	err = renewer.renew()

	if err != nil {
		t.Errorf("error renewing token: %s", err)
	}
}