package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	mathrand "math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ------------------------------------------------------------
// 1. Constants & global data
// ------------------------------------------------------------
const (
	port         = ":8443"
	dictFile     = "dictionary.txt"
	certFile     = "cert.pem"
	keyFile      = "key.pem"
	minPwdLen    = 20
	maxPwdLen    = 27
	symbols      = "!@#$%^&*()-_=+[]{};:,.<>?"
	upperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerLetters = "abcdefghijklmnopqrstuvwxyz"
	digits       = "0123456789"
)

// ------------------------------------------------------------
// 2. Load the dictionary once at startup
// ------------------------------------------------------------
var wordList []string

func loadDictionary() error {
	f, err := os.Open(dictFile)
	if err != nil {
		return fmt.Errorf("open %s: %w", dictFile, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" { // skip empty lines
			continue
		}
		wordList = append(wordList, word)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", dictFile, err)
	}

	if len(wordList) < 10000 {
		return fmt.Errorf("%s contains only %d words – at least 10 000 required", dictFile, len(wordList))
	}
	return nil
}

// ------------------------------------------------------------
// 3. Random helpers
// ------------------------------------------------------------
func randInt(max int64) (int64, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}
	return nBig.Int64(), nil
}

func randFromSet(set string) (byte, error) {
	idx, err := randInt(int64(len(set)))
	if err != nil {
		return 0, err
	}
	return set[int(idx)], nil
}

// ------------------------------------------------------------
// 4. Password generator
// ------------------------------------------------------------
func generatePassword() (string, error) {
	// 1. Pick two random words from the dictionary. Retry if the
	// combined word part (including separators around each word) plus the
	// required pool would exceed maxPwdLen.
	const requiredPoolLen = 2 + 2 + 4 + 2 // number of forced chars added below
	sepSet := digits + symbols            // separators may be a digit or a symbol
	attempts := 0
	var wordPart string
	for {
		wIdx1, err := randInt(int64(len(wordList)))
		if err != nil {
			return "", err
		}
		wIdx2, err := randInt(int64(len(wordList)))
		if err != nil {
			return "", err
		}

		// choose four separators: before/after word1, before/after word2
		s1, err := randFromSet(sepSet)
		if err != nil {
			return "", err
		}
		s2, err := randFromSet(sepSet)
		if err != nil {
			return "", err
		}
		s3, err := randFromSet(sepSet)
		if err != nil {
			return "", err
		}
		s4, err := randFromSet(sepSet)
		if err != nil {
			return "", err
		}

		// assemble the word part with separators surrounding each word
		word1 := wordList[int(wIdx1)]
		word2 := wordList[int(wIdx2)]
		wordPart = string([]byte{s1}) + word1 + string([]byte{s2}) + string([]byte{s3}) + word2 + string([]byte{s4})

		if len(wordPart)+requiredPoolLen <= maxPwdLen {
			break
		}
		attempts++
		if attempts >= 100 {
			return "", fmt.Errorf("could not find two words that produce a password <= %d after %d attempts", maxPwdLen, attempts)
		}
		// small pause to mix entropy source a bit (not strictly necessary)
		time.Sleep(5 * time.Millisecond)
	}

	// 2. Build a pool of required characters
	pool := []byte{}
	for i := 0; i < 2; i++ {
		c, err := randFromSet(upperLetters)
		if err != nil {
			return "", err
		}
		pool = append(pool, c)
	}
	for i := 0; i < 2; i++ {
		c, err := randFromSet(lowerLetters)
		if err != nil {
			return "", err
		}
		pool = append(pool, c)
	}
	for i := 0; i < 4; i++ {
		c, err := randFromSet(digits)
		if err != nil {
			return "", err
		}
		pool = append(pool, c)
	}
	for i := 0; i < 2; i++ {
		c, err := randFromSet(symbols)
		if err != nil {
			return "", err
		}
		pool = append(pool, c)
	}

	// 3. Compute how many more chars we need to hit min length.
	// `wordPart` already includes separators surrounding each word.
	totalLen := len(wordPart) + len(pool)
	moreNeeded := 0
	if totalLen < minPwdLen {
		moreNeeded = minPwdLen - totalLen
	} else if totalLen > maxPwdLen {
		return "", fmt.Errorf("word part + pool too long: %d chars, exceeds maximum %d", totalLen, maxPwdLen)
	}

	// 4. Fill the rest with random characters from all sets
	allSet := upperLetters + lowerLetters + digits + symbols
	for i := 0; i < moreNeeded; i++ {
		c, err := randFromSet(allSet)
		if err != nil {
			return "", err
		}
		pool = append(pool, c)
	}

	// 5. Shuffle the pool (so the word part isn’t always at the front)
	mathrand.Shuffle(len(pool), func(i, j int) {
		pool[i], pool[j] = pool[j], pool[i]
	})

	// The `wordPart` already contains separators around each word; append
	// the shuffled random pool directly (e.g. "-word1-#-word2-AB12!x").
	return wordPart + string(pool), nil
}

// generatePasswordMode produces a password according to the requested mode.
// Supported modes: "normal" (original generator), "readability", "random".
// generatePasswordMode produces a password according to the requested mode.
// It returns (password, fellBackToNormal, error).
func generatePasswordMode(mode string) (string, bool, error) {
	switch mode {
	case "normal":
		p, err := generatePassword()
		return p, false, err
	case "readability":
		// Readability mode: pick three dictionary words whose combined
		// length plus the fixed number (4 chars) and 4 symbols fits within
		// maxPwdLen. If we can't find such a triple after attempts, fall
		// back to the normal generator.
		maxWordsLen := maxPwdLen - 4 - 4 // 4-digit number + 4 symbols
		if maxWordsLen < 3 {
			p, err := generatePassword()
			return p, false, err
		}
		var sel [3]string
		found := false
		for attempts := 0; attempts < 1000 && !found; attempts++ {
			for i := 0; i < 3; i++ {
				idx, err := randInt(int64(len(wordList)))
				if err != nil {
					return "", false, err
				}
				sel[i] = wordList[int(idx)]
			}
			total := len(sel[0]) + len(sel[1]) + len(sel[2])
			if total <= maxWordsLen {
				found = true
			}
		}
		if !found {
			// graceful fallback to normal generator
			p, err := generatePassword()
			return p, true, err
		}
		combined := sel[0] + sel[1] + sel[2]
		runes := []rune(combined)
		// Decide how many letters to capitalize (bounded reasonably).
		caps := 1
		if len(runes) >= 16 {
			caps = 2
		}
		if len(runes) >= 28 {
			caps = 3
		}
		made := 0
		tries := 0
		for made < caps && tries < 200 {
			tries++
			idx, err := randInt(int64(len(runes)))
			if err != nil {
				return "", false, err
			}
			r := runes[int(idx)]
			if unicode.IsLetter(r) {
				runes[int(idx)] = unicode.ToUpper(r)
				made++
			}
		}
		numRand, err := randInt(9000)
		if err != nil {
			return "", false, err
		}
		number := strconv.Itoa(int(numRand) + 1000)
		syms := make([]byte, 0, 4)
		for i := 0; i < 4; i++ {
			c, err := randFromSet(symbols)
			if err != nil {
				return "", false, err
			}
			syms = append(syms, c)
		}
		// Final check: ensure total length does not exceed maxPwdLen (safety)
		result := string(runes) + number + string(syms)
		if len(result) > maxPwdLen {
			p, err := generatePassword()
			return p, true, err
		}
		return result, false, nil
	case "random":
		// length 20..27
		lnRand, err := randInt(8)
		if err != nil {
			return "", false, err
		}
		L := 20 + int(lnRand)
		pool := make([]byte, 0, L)
		// ensure categories
		for i := 0; i < 2; i++ {
			c, err := randFromSet(upperLetters + lowerLetters)
			if err != nil {
				return "", false, err
			}
			pool = append(pool, c)
		}
		for i := 0; i < 2; i++ {
			c, err := randFromSet(digits)
			if err != nil {
				return "", false, err
			}
			pool = append(pool, c)
		}
		for i := 0; i < 2; i++ {
			c, err := randFromSet(symbols)
			if err != nil {
				return "", false, err
			}
			pool = append(pool, c)
		}
		allSet := upperLetters + lowerLetters + digits + symbols
		for len(pool) < L {
			c, err := randFromSet(allSet)
			if err != nil {
				return "", false, err
			}
			pool = append(pool, c)
		}
		mathrand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
		return string(pool), false, nil
	default:
		p, err := generatePassword()
		return p, false, err
	}
}

// ------------------------------------------------------------
// 5. HTTP handler
// ------------------------------------------------------------
func pwdHandler(w http.ResponseWriter, r *http.Request) {
	// Render an empty grid of twelve password placeholders. The client
	// will populate these by calling /api/passwords on load so the
	// initial server response contains no passwords.
	var pwHTML strings.Builder
	for i := 0; i < 12; i++ {
		pwHTML.WriteString("<div class=\"pwd\" onclick=\"copyPwd(this)\"></div>\n")
	}

	var page strings.Builder
	page.WriteString(`<!doctype html>
	<html lang="en">
	<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>Password-O-Matic</title>
	<!-- Google Font: Urbanist -->
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Urbanist:ital,wght@0,100..900;1,100..900&display=swap" rel="stylesheet">
	<style>
/* Make sizing predictable and prevent accidental overflow */
*,*::before,*::after{box-sizing:border-box}
/* Scale fonts up globally by 10% (rem units will follow) */
html
body{font-family:'Urbanist', system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;padding:2rem;display:flex;align-items:center;justify-content:center;min-height:100vh;color:#e6e1ee;background:linear-gradient(135deg,#2b0f3a 0%,#4a2550 35%,#14071a 100%);background-size:200% 200%;animation:bgShift 12s ease infinite;overflow-x:hidden;margin:0}

/* Card */
/* Use fluid width with a max so the container can shrink on small viewports */
main{background:#0f0f12;border-radius:.5rem;padding:1.75rem;width:100%;max-width:1080px;box-shadow:0 8px 30px rgba(0,0,0,.6);transform:translateY(-3vh);border:1px solid rgba(255,45,149,0.06)}

/* Header */
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem}
h1{text-align:left;color:#f3e8ff;margin:0;font-size:1.35rem}

	.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.9rem}

/* Controls: place regen (rounded square) slightly left, menu at far right */
.controls{display:flex;align-items:center;gap:.5rem}
.regen{width:44px;height:44px;display:inline-flex;align-items:center;justify-content:center;background:linear-gradient(90deg,#ff2d95,#c4007a);color:white;border:none;padding:0;border-radius:.35rem;font-weight:700;cursor:pointer;box-shadow:0 6px 18px rgba(196,0,122,0.12);margin-right:6px}
.regen:hover{filter:brightness(.95)}
.regen svg{width:20px;height:20px;display:block}

/* hamburger menu button */
.menuBtn{width:44px;height:44px;display:inline-flex;align-items:center;justify-content:center;background:linear-gradient(90deg,#ff2d95,#c4007a);color:white;border:none;border-radius:.35rem;cursor:pointer}
.menuBtn svg{width:20px;height:14px;display:block}
.menuPopup{position:absolute;right:12px;top:56px;background:#121015;border:1px solid rgba(255,45,149,0.06);padding:.5rem;border-radius:.5rem;box-shadow:0 8px 30px rgba(0,0,0,.6);display:none;min-width:200px}
.menuPopup.active{display:block}
.menuPopup button{display:block;width:100%;text-align:left;padding:.5rem .6rem;border-radius:.35rem;background:transparent;border:none;color:#e6e1ee;cursor:pointer}
.menuPopup button:hover{background:rgba(255,45,149,0.04)}
.menuPopup button.active{background:linear-gradient(90deg,#ff2d95,#c4007a);color:white}

.pwd{background:#1b1220;padding:1.2rem 1rem;border-radius:.4rem;font-weight:600;text-align:center;white-space:normal;overflow-wrap:anywhere;word-break:break-word;font-size:1.08rem;min-height:3.6rem;cursor:pointer;user-select:text;color:#ffffff;border:1px solid rgba(255,45,149,0.12);min-width:0}
.pwd:hover{background:rgba(255,45,149,0.06);box-shadow:0 6px 18px rgba(77,0,102,0.12)}

.note{text-align:center;margin-top:.75rem;color:#bfb7d6;font-size:.95rem}
.regen svg{width:20px;height:20px;display:block}

/* spin state */
.regen.spin svg{animation:spin .9s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* swap animation */
.pwd{transition:transform .28s ease,opacity .28s ease}
.pwd.fade-out{opacity:0;transform:translateY(-8px) scale(.985)}
.pwd.fade-in{opacity:0;transform:translateY(8px) scale(.985);animation:pwdIn .28s forwards}
@keyframes pwdIn{to{opacity:1;transform:translateY(0) scale(1)}}

/* Toast popup */
.toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%) translateY(20px);background:rgba(34,22,40,0.95);color:#fff;padding:10px 16px;border-radius:6px;opacity:0;pointer-events:none;transition:opacity .18s ease,transform .18s ease;border:1px solid rgba(255,45,149,0.12)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
@keyframes bgShift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}

/* Responsive */
@media (max-width: 900px) {
	main{width:calc(100% - 40px);max-width:calc(100% - 40px);padding:1.25rem}
	.grid{grid-template-columns:repeat(2,1fr);gap:.75rem}
}
@media (max-width: 520px) {
	main{width:calc(100% - 24px);max-width:calc(100% - 24px);padding:1rem}
	.grid{grid-template-columns:repeat(1,1fr);gap:.5rem}
	.pwd{font-size:0.95rem;padding:.7rem;min-height:auto}
	.regen{width:40px;height:40px}
}
	</style>
	</head>
	<body>
	<main>
		<div class="header">
			<h1>Password-O-Matic</h1>
						<div class="controls" style="position:relative">
								<button id="regen" class="regen" type="button" aria-label="Generate new passwords" title="New set">
												<!-- refresh icon (rounded square) -->
												<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" focusable="false">
													<path d="M21 12a9 9 0 10-2.64 6.12" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
													<path d="M21 3v6h-6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
												</svg>
								</button>
								<!-- hamburger menu placed at the far right -->
								<div style="position:relative">
										<button id="menuBtn" class="menuBtn" aria-label="Menu" title="Menu">
												<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" focusable="false">
													<path d="M3 6h18M3 12h18M3 18h18" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
												</svg>
										</button>
										<div id="menuPopup" class="menuPopup" role="menu" aria-hidden="true">
												<button data-mode="readability">Readability</button>
												<button data-mode="normal" class="active">Normal</button>
												<button data-mode="random">Random</button>
										</div>
								</div>
						</div>
				</div>
		<div class="grid">`)

	// insert generated password tiles
	page.WriteString(pwHTML.String())

	// finish template
	page.WriteString(`</div>
		<p class="note">Click a password to copy it to the clipboard.</p>
		<script>
		function showToast(msg){
			let t = document.getElementById('toast');
			if(!t){
				t = document.createElement('div');
				t.id = 'toast';
				t.className = 'toast';
				document.body.appendChild(t);
			}
			t.textContent = msg;
			// trigger show
			t.classList.add('show');
			// hide after 1s
			clearTimeout(t._hideTimer);
			t._hideTimer = setTimeout(()=> t.classList.remove('show'), 1000);
		}

		function copyPwd(el){
			const txt = el.innerText;
			navigator.clipboard.writeText(txt).then(()=>{
				showToast('Copied');
			}).catch(()=>showToast('Copy failed'));
		}

		// Fetch new passwords via AJAX and animate swap in-place.
				let currentMode = 'normal';
				function setCookie(name, value, days){
					const d = new Date();
					d.setTime(d.getTime() + (days*24*60*60*1000));
					document.cookie = name + '=' + encodeURIComponent(value) + ';expires=' + d.toUTCString() + ';path=/';
				}
				function getCookie(name){
					const pairs = document.cookie.split(';').map(s=>s.trim());
					for(const p of pairs){
						if(!p) continue;
						const parts = p.split('=');
						if(parts[0] === name) return decodeURIComponent(parts.slice(1).join('='));
					}
					return '';
				}
		async function regenPasswords(){
			const b = document.getElementById('regen');
			if(b) b.disabled = true;
			try{
				if(b) b.classList.add('spin');
				const res = await fetch('/api/passwords?mode='+encodeURIComponent(currentMode));
				if(!res.ok) throw new Error('status '+res.status);
				const body = await res.json();
				const pwds = Array.isArray(body) ? body : (body.pwds || []);
				const fellBack = body && body.fallback;
				const cells = Array.from(document.querySelectorAll('.grid .pwd'));
				// fade out all cells in parallel
				cells.forEach(c => c.classList.add('fade-out'));
				// wait for the fade-out to finish
				await new Promise(r => setTimeout(r, 240));
				// replace content and fade in
				for(let i=0;i<cells.length && i<pwds.length;i++){
					const el = cells[i];
					el.textContent = pwds[i];
					// remove any stale classes
					el.classList.remove('fade-out');
					el.classList.add('fade-in');
					// remove fade-in after animation
					setTimeout(()=>el.classList.remove('fade-in'), 320);
				}
				if(fellBack){
					showToast('Fell back to normal');
				} else {
					showToast('New set');
				}
			}catch(err){
				showToast('Failed to fetch');
			} finally{
				if(b) { b.disabled = false; b.classList.remove('spin'); }
			}
		}

		document.addEventListener('DOMContentLoaded', function(){
			const b = document.getElementById('regen');
			if(b){
				b.addEventListener('click', regenPasswords);
			}
			const menuBtn = document.getElementById('menuBtn');
			const popup = document.getElementById('menuPopup');
			// restore saved mode from cookie
			const saved = getCookie('pwd_mode');
			if(saved){
				currentMode = saved;
			}
			if(popup){
				// set active button according to currentMode
				const activeBtn = popup.querySelector('button[data-mode="'+currentMode+'"]');
				if(activeBtn){
					popup.querySelectorAll('button').forEach(b=>b.classList.remove('active'));
					activeBtn.classList.add('active');
				}
				// populate initial set immediately
				regenPasswords();
			}
			if(menuBtn && popup){
				menuBtn.addEventListener('click', (e)=>{
					e.stopPropagation();
					popup.classList.toggle('active');
				});
				// close when clicking outside
				document.addEventListener('click', ()=> popup.classList.remove('active'));
				// menu option clicks
				popup.querySelectorAll('button[data-mode]').forEach(btn=>{
					btn.addEventListener('click', (e)=>{
						e.stopPropagation();
						const mode = btn.getAttribute('data-mode');
						currentMode = mode;
						// save to cookie for 1 year
						setCookie('pwd_mode', mode, 365);
						// update active state
						popup.querySelectorAll('button').forEach(b=>b.classList.remove('active'));
						btn.classList.add('active');
						popup.classList.remove('active');
						// regen immediately with new complexity
						regenPasswords();
					});
				});
			}
		});
		</script>
	</main>
	</body>
	</html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, page.String())
}

// apiHandler returns a JSON array of N generated passwords.
func apiHandler(w http.ResponseWriter, r *http.Request) {
	const n = 12
	pwds := make([]string, 0, n)
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "normal"
	}
	anyFallback := false
	for i := 0; i < n; i++ {
		p, fellBack, err := generatePasswordMode(mode)
		if err != nil {
			http.Error(w, "Could not generate password: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if fellBack {
			anyFallback = true
		}
		pwds = append(pwds, p)
	}
	resp := map[string]interface{}{"pwds": pwds, "fallback": anyFallback}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "encode json: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func generateSelfSignedCert() error {
	// If both cert and key exist, nothing to do.
	if _, err := os.Stat(certFile); err == nil {
		if _, err2 := os.Stat(keyFile); err2 == nil {
			return nil
		}
	}

	log.Println("Generating new self-signed cert…")

	// Generate a private key.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}

	// Create a serial number.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	// Certificate template.
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Self-sign the certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	// PEM encode the certificate.
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if certOut == nil {
		return fmt.Errorf("failed to encode certificate")
	}

	// PEM encode the private key.
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if keyOut == nil {
		return fmt.Errorf("failed to encode private key")
	}

	// Write files with appropriate permissions.
	if err := os.WriteFile(certFile, certOut, 0644); err != nil {
		return fmt.Errorf("write cert file: %w", err)
	}
	if err := os.WriteFile(keyFile, keyOut, 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}

	return nil
}

// ------------------------------------------------------------
// 7. Main
// ------------------------------------------------------------
func main() {

	// If run with `--sample`, print a number of generated passwords to stdout
	// and exit. This is a debug mode to verify lengths without starting the server.
	if len(os.Args) > 1 && os.Args[1] == "--sample" {
		if err := loadDictionary(); err != nil {
			log.Fatalf("Failed to load dictionary: %v", err)
		}
		for i := 0; i < 200; i++ {
			pwd, err := generatePassword()
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			fmt.Printf("%d %s\n", len(pwd), pwd)
		}
		return
	}

	if err := loadDictionary(); err != nil {
		log.Fatalf("Failed to load dictionary: %v", err)
	}

	if err := generateSelfSignedCert(); err != nil {
		log.Fatalf("Could not create TLS cert: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", pwdHandler)
	// API endpoint for fetching a fresh set of passwords via AJAX
	mux.HandleFunc("/api/passwords", apiHandler)

	srv := &http.Server{
		Addr:    port,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("Serving on https://localhost%s (copy button will work with HTTPS)", port)
	if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
