package signatures

import "testing"

func TestDigestIsStableAndSensitiveToCatalogChanges(t *testing.T) {
	first := []Fingerprint{{ID: "one", Service: "Serviço", CNames: []string{"provider.example"}}}
	digestA, err := Digest(first)
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := Digest(first)
	if err != nil {
		t.Fatal(err)
	}
	if digestA == "" || digestA != digestB {
		t.Fatalf("digest instável: %q e %q", digestA, digestB)
	}
	first[0].CNames[0] = "other.example"
	digestC, err := Digest(first)
	if err != nil {
		t.Fatal(err)
	}
	if digestA == digestC {
		t.Fatal("alteração do catálogo não modificou o digest")
	}
}
