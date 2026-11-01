package stage

import (
	"strings"
	"testing"

	"ghostlock/internal/assets"
)

func TestKMIfromKernel(t *testing.T) {
	cases := map[string]string{
		"5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412":       "android13-5.15",
		"5.15.167-android13-8-00017-gb1f32b310a30-ab12826353":  "android13-5.15",
		"6.1.138-android14-11-g44bda9e8f6e9-ab13792638":        "android14-6.1",
		"6.6.118-android15-8-g93e223c276e7-abogki500782043-4k": "android15-6.6",
		"6.12.38-android16-5-g1d46253471dd-ab15048002-4k":      "android16-6.12",
		"":            "",
		"9.9.9-weird": "",
	}
	for in, want := range cases {
		if got := KMIfromKernel(in); got != want {
			t.Errorf("KMIfromKernel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProfileForPicksDeviceConf(t *testing.T) {
	loader := assets.New("")
	name, p, err := ProfileFor(loader, "5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412")
	if err != nil {
		t.Fatalf("ProfileFor: %v", err)
	}
	if name != "5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412.conf" {
		t.Fatalf("name = %q", name)
	}
	if p.Release != "5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412" {
		t.Fatalf("release = %q", p.Release)
	}
	if p.Route != "multicast_waiter" {
		t.Fatalf("route = %q", p.Route)
	}
}

func TestRunScriptBakesEnforce(t *testing.T) {
	// The embedded root script only honours GHOSTLOCK_KSU_ENFORCE from the
	// environment, and nothing ever wrote $H/ksu_target, so a hardcoded default
	// here silently turned every --temp-root loop run into a full late-load.
	body := runScript(RemoteDir, true, 9)
	if !strings.Contains(body, "export GHOSTLOCK_KSU_ENFORCE=9") {
		t.Fatalf("enforce not baked: %s", body)
	}
	if !strings.Contains(body, `echo 9 > "$H/ksu_target"`) {
		t.Fatalf("ksu_target not written: %s", body)
	}
	if !strings.Contains(body, "--force-attack") {
		t.Fatalf("force-attack missing: %s", body)
	}
	if plain := runScript(RemoteDir, false, 0); !strings.Contains(plain, "export GHOSTLOCK_KSU_ENFORCE=0") {
		t.Fatalf("default enforce must be 0: %s", plain)
	}
}

func TestProfileForRejectsTemplatesAndUnknown(t *testing.T) {
	loader := assets.New("")
	for _, kernel := range []string{"5.15-template", "6.6.0-unknown", ""} {
		if _, _, err := ProfileFor(loader, kernel); err == nil {
			t.Errorf("ProfileFor(%q) should fail", kernel)
		}
	}
}
