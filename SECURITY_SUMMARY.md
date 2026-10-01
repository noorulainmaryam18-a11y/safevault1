### 3.3 XSS review - `InputValidator.cs`
Prompt: "Check this for XSS bypasses and suggest improvements."

Copilot judged the code reasonably defensive for `/feedback` and `/vault`, because values are
encoded before they are returned or displayed, but it pointed out limits:

1. The denylist regex (`SuspiciousRx`) cannot cover every HTML, SVG, CSS, URL or JavaScript
   attack form, so it must not be the primary XSS defence. I agree: the real protection is
   output encoding plus the Content-Security-Policy; the regex is an extra layer that also
   rejects obviously malicious input early.
2. `HtmlEncode` is only correct for HTML text, not for attributes, JavaScript, CSS or URLs.
   Currently the app only returns HTML-text values, but any new output context needs its own
   encoder.
3. Encoding inside a JSON response can cause double encoding. Copilot recommends returning
   the original validated text and encoding only at the HTML rendering step. I kept the
   current behaviour for now because my test `Feedback_Output_IsEncoded` and the API are built
   on it; changing it is a planned improvement.
4. Add an explicit length check before the username regex and a request-body size limit
   (planned).

**Applied:** I strengthened the CSP with `base-uri 'self'` and `frame-ancestors 'none'`, and
re-ran `dotnet test` (31 of 31 pass). **Planned:** more XSS payload tests (event handlers,
SVG, CSS, URL schemes, HTML entities), body-size limits, and moving encoding to the rendering
layer.