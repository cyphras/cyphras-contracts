package service

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestTheSubcommandIsTheFirstArgument(t *testing.T) {
	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"indexer"}
	if Command("serve") != "serve" {
		t.Fatal("default command")
	}
	os.Args = []string{"indexer", "rebuild"}
	if Command("serve") != "rebuild" {
		t.Fatal("rebuild")
	}
	os.Args = []string{"indexer", "-v"}
	if Command("serve") != "serve" {
		t.Fatal("a flag is not a command")
	}
}

func TestAlertWebhooksComeFromASecretFile(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := Alerter("keeper", log)
	if err != nil || len(a.Channels) != 0 {
		t.Fatalf("without webhooks: %v", err)
	}
	path := filepath.Join(t.TempDir(), "hooks")
	if err := os.WriteFile(path, []byte("slack https://hooks.example/a\ntext https://ntfy.example/b\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ALERT_WEBHOOKS_FILE", path)
	a, err = Alerter("keeper", log)
	if err != nil || len(a.Channels) != 2 {
		t.Fatalf("with webhooks: %v", err)
	}
}
