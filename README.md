# [Stored-XSS] in [Bagisto] <= [v2.3.9]
---
## BUG Author: [CyberTechAjju]
---
### Product Information:
---
- Vendor Homepage: (https://bagisto.com/en/)
- Software Link: (https://github.com/bagisto/bagisto)
- Affected Version: [<= v2.3.9]
- BUG Author: CyberTechAjju

### Vulnerability Details
---
- Type: Stored Cross-Site Scripting (XSS)
- Affected URL: http://[TARGET]/admin/settings/themes/edit/{id}
- Vulnerable Parameter: HTML field in Static Content
- Authentication Required: Yes (Admin)

#### Vulnerable Files:
- File Name: ThemeCustomizationRepository.php
- Path: packages/Webkul/Theme/src/Repositories/ThemeCustomizationRepository.php
- Line Number: 33-34

#### Vulnerability Type
- Stored XSS Vulnerability (CWE-79: Improper Neutralization of Input During Web Page Generation)
- Severity Level: MEDIUM (CVSS: 4.8)
- OWASP Category: A7:2017-Cross-Site Scripting (XSS)

#### Root Cause
The application attempts to sanitize user input by removing `<script>` tags using a regex pattern. However, this approach is insufficient as it fails to filter JavaScript event handlers such as `onerror`, `onload`, `onclick`, `onmouseover`, etc.

***Vulnerable Code at Line 33-34:***

```php
$data[$locale]['options']['html'] = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $html);
$data[$locale]['options']['css'] = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $css);
```

The sanitized HTML is then rendered directly to the frontend without proper output encoding:

- File: packages/Webkul/Shop/src/Resources/views/home/index.blade.php
- Line 61: `{!! $data['html'] !!}`

### Impact:
---
| Impact Type | Description |
|-------------|-------------|
| Session Hijacking | Attacker can steal session cookies of all visitors |
| Credential Theft | Inject fake login forms to capture user credentials |
| Malware Distribution | Redirect visitors to malicious websites |
| Customer Data Theft | Access sensitive customer information |
| Website Defacement | Modify storefront appearance |

### Description:
---
#### 1. Vulnerability Details:
- The HTML input in Theme Customization is filtered only for `<script>` tags using regex
- Event handlers like `onerror`, `onload`, `onclick`, `onmouseover` bypass the filter completely
- The output is rendered using Laravel's raw syntax `{!! !!}` without proper escaping
- Payload persists in database and affects all users visiting the storefront

#### 2. Attack Vectors:
- Authenticated admin injects malicious JavaScript via Theme Customization
- Payload is stored in `theme_customizations` database table
- Every visitor to the storefront triggers the malicious script
- Attack can be used for mass session hijacking or phishing

#### 3. Attack Payload Examples: 
```html
<img src=x onerror="alert(document.cookie)">
```
```html
<svg onload="alert('XSS')">
```
```html
<body onpageshow="alert('XSS')">
```
```html
<marquee onstart="alert('XSS')">
```

### Proof of Concept:
---

#### Step 1: Setup Lab Environment
```bash
# Using Docker (Recommended)
docker pull webkul/bagisto:2.2.3
docker run -d -p 8080:80 --name bagisto-lab webkul/bagisto:2.2.3

# Access Points:
# Frontend: http://localhost:8080
# Admin Panel: http://localhost:8080/admin
# Default Credentials: admin@example.com / admin123
```

#### Step 2: Login to Admin Panel
1. Navigate to `http://localhost:8080/admin`
2. Enter Email: `admin@example.com`
3. Enter Password: `admin123`
4. Click **Sign In**
<img width="1366" height="663" alt="image" src="https://github.com/user-attachments/assets/ed241dc6-ec84-4dd1-b376-68ef2447f8c2" />

#### Step 3: Navigate to Theme Settings
1. In the left sidebar, click **Settings**
2. Click on **Themes**
3. Locate any entry with Type: **Static Content**

#### Step 4: Inject XSS Payload
1. Click the **Edit** (pencil icon) on any Static Content entry
2. In the **HTML** editor field, clear existing content
3. Insert the following payload:

```html
<img src=x onerror="alert(document.cookie)">
```

4. Click **Save** button
<img width="1366" height="661" alt="image" src="https://github.com/user-attachments/assets/a896efb2-9f13-4bad-81c3-14b79e02138a" />

#### Step 5: Verify XSS Execution
1. Open a new browser tab or incognito window
2. Navigate to: `http://localhost:8080/`
3. **Result:** JavaScript alert box appears displaying cookies
<img width="1366" height="663" alt="image" src="https://github.com/user-attachments/assets/c84e5a84-d7dd-4227-9206-b5859862fbb9" />

#### Exploitation Result:
- The XSS payload successfully bypasses the `<script>` tag filter
- Malicious JavaScript executes in the context of every visitor's browser
- Cookies, session tokens, and sensitive data can be exfiltrated

### Code Analysis:
---

#### Vulnerable Code (Input Sanitization) - Insufficient Filtering:
```php
// File: packages/Webkul/Theme/src/Repositories/ThemeCustomizationRepository.php
// Line 33-34

$data[$locale]['options']['html'] = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $html);
$data[$locale]['options']['css'] = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $css);
```
**Issue:** Only `<script>` tags are removed. All other XSS vectors remain unfiltered.

#### Vulnerable Code (Output Rendering) - Raw HTML Output:
```php
// File: packages/Webkul/Shop/src/Resources/views/home/index.blade.php
// Line 61

{!! $data['html'] !!}
```
**Issue:** Laravel's `{!! !!}` syntax outputs raw HTML without escaping, allowing injected JavaScript to execute.

### Suggested Remediation:
---

#### 1. Replace Regex with HTMLPurifier Library:
```php
use HTMLPurifier;
use HTMLPurifier_Config;

$config = HTMLPurifier_Config::createDefault();
$config->set('HTML.Allowed', 'div,span,p,a[href],img[src|alt],h1,h2,h3,h4,h5,h6,ul,ol,li,br,strong,em');
$config->set('HTML.TargetBlank', true);
$purifier = new HTMLPurifier($config);

$data[$locale]['options']['html'] = $purifier->purify($html);
```

#### 2. Implement Content Security Policy (CSP) Headers:
```php
// Add to middleware or response headers
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
```

#### 3. Use Blade Escaped Output Where Possible:
```php
// Instead of {!! $data['html'] !!}
// Use {{ $data['html'] }} for escaped output
```

### Additional Information:
---
- **References:**
  - OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
  - CWE-79: https://cwe.mitre.org/data/definitions/79.html
  - HTMLPurifier Library: http://htmlpurifier.org/
  - Laravel Security Best Practices: https://laravel.com/docs/10.x/blade#displaying-unescaped-data

### Mitigation Timeline:
---
| Priority | Action |
|----------|--------|
| Immediate | Implement HTMLPurifier for HTML input sanitization |
| Short-term | Add Content Security Policy headers |
| Long-term | Conduct comprehensive security audit of all user inputs |

---

This vulnerability poses a significant risk to all storefront visitors and requires immediate attention to prevent potential customer data compromise.

---
### Discovered By: CyberTechAjju
### Discovery Date: 2026-01-02
