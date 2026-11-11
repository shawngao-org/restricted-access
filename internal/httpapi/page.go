package httpapi

import "html/template"

var pageTemplate = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="{{.Lang}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.Title}}</title>
<style>
:root { color-scheme: light dark; --bg: #f3efe6; --card: #fffdf8; --ink: #1c1915; --muted: #6d645b; --line: #e4dccf; --mark: #8a3d2f; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #161411; --card: #221f1b; --ink: #f3efe6; --muted: #b7aea3; --line: #3a342c; --mark: #e0a090; }
}
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: grid; place-items: center;
  background: var(--bg); color: var(--ink);
  font: 18px/1.65 "Iowan Old Style", Palatino, "Palatino Linotype", "Songti SC", "Noto Serif CJK SC", "Source Han Serif SC", serif;
}
main { width: min(40rem, calc(100% - 2rem)); background: var(--card); border: 1px solid var(--line); padding: 2.5rem 2.25rem; }
.eyebrow { margin: 0 0 0.75rem; font: 600 0.75rem/1.4 ui-sans-serif, system-ui, sans-serif; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mark); }
h1 { margin: 0 0 1rem; font-size: 2rem; font-weight: 600; letter-spacing: -0.02em; }
p { margin: 0 0 0.8rem; }
.en { color: var(--muted); font-size: 0.95rem; }
.ref { margin-top: 1.5rem; color: var(--muted); font: 0.75rem/1.4 ui-sans-serif, system-ui, sans-serif; }
a { color: inherit; }
</style>
</head>
<body>
<main>
  <p class="eyebrow">{{.Eyebrow}}</p>
  <h1>{{.Title}}</h1>
  <p>{{.Message}}</p>
  {{if .English}}<p class="en">{{.English}}</p>{{end}}
  {{if .Link}}<p><a href="{{.Link}}">{{.LinkText}}</a></p>{{end}}
  <p class="ref">Reference Number {{.Ref}}</p>
</main>
</body>
</html>
`))

type pageData struct {
	Lang     string
	Eyebrow  string
	Title    string
	Message  string
	English  string
	Link     string
	LinkText string
	Ref      string
}
