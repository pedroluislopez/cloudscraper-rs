use boa_engine::{Context, Source};
use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};

use super::{InterpreterError, InterpreterResult, JavascriptInterpreter};

/// Default interpreter backed by the Boa JavaScript engine.
#[derive(Debug, Default)]
pub struct BoaJavascriptInterpreter;

impl BoaJavascriptInterpreter {
    pub fn new() -> Self {
        Self
    }

    fn extract_scripts<'a>(&self, html: &'a str) -> Vec<&'a str> {
        static SCRIPT_RE: Lazy<Regex> = Lazy::new(|| {
            RegexBuilder::new(r"(?is)<script[^>]*>(?P<body>.*?)</script>")
                .dot_matches_new_line(true)
                .case_insensitive(true)
                .build()
                .unwrap()
        });

        SCRIPT_RE
            .captures_iter(html)
            .filter_map(|caps| caps.name("body").map(|m| m.as_str()))
            .collect()
    }

    fn build_prelude(&self, host: &str) -> String {
        format!(
            r#"
var __host = "{host}";
var __scheme = "https://";
var location = {{
    href: __scheme + __host + "/",
    hostname: __host,
    protocol: "https:",
    port: ""
}};
var window = {{ location: location }};
var navigator = {{
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    language: "en-US",
    languages: ["en-US", "en"],
    platform: "Win32"
}};
window.navigator = navigator;
var history = {{ replaceState: function() {{}} }};
window.history = history;
var performance = {{ now: function() {{ return Date.now(); }} }};
window.performance = performance;
var __state = {{
    values: {{}},
    setValue: function(id, value) {{ this.values[id] = value; }},
    getValue: function(id) {{ return this.values[id]; }}
}};
function __absUrl(input) {{
    if (!input) return "";
    if (input.startsWith("http://") || input.startsWith("https://")) return input;
    if (input.startsWith("//")) return location.protocol + input;
    if (input.startsWith("/")) return __scheme + __host + input;
    return __scheme + __host + (input.startsWith("?") ? "/" + input : "/" + input.replace(/^\/+/, ""));
}}
function __makeElement(id) {{
    var element = {{
        id: id,
        style: {{}},
        attributes: {{}},
        children: [],
        addEventListener: function() {{}},
        removeEventListener: function() {{}},
        appendChild: function(child) {{ this.children.push(child); return child; }},
        setAttribute: function(name, value) {{ this.attributes[name] = value; }},
        getAttribute: function(name) {{ return this.attributes[name] || ""; }},
        submit: function() {{}}
    }};
    Object.defineProperty(element, "value", {{
        get: function() {{ return __state.getValue(id); }},
        set: function(v) {{ __state.setValue(id, v); }}
    }});
    Object.defineProperty(element, "innerHTML", {{
        get: function() {{ return this._innerHTML || ""; }},
        set: function(val) {{
            this._innerHTML = val;
            var match = /href\s*=\s*['"]([^'"]+)['"]/i.exec(val || "");
            if (match) {{
                this.firstChild = {{ href: __absUrl(match[1]) }};
            }} else {{
                this.firstChild = {{ href: "" }};
            }}
        }}
    }});
    Object.defineProperty(element, "href", {{
        get: function() {{ return this._href || ""; }},
        set: function(val) {{ this._href = __absUrl(val); }}
    }});
    return element;
}}
var document = {{
    _cache: {{}},
    location: location,
    createElement: function(tag) {{ return __makeElement(tag); }},
    querySelector: function(sel) {{ return __makeElement(sel); }},
    querySelectorAll: function(sel) {{ return []; }},
    getElementById: function(id) {{
        if (!this._cache[id]) {{
            var el = __makeElement(id);
            if (id === "challenge-form") {{
                try {{
                    el.elements = new Proxy({{}}, {{
                        get: function(_, prop) {{
                            if (typeof prop === "string") {{
                                return document.getElementById(prop);
                            }}
                            return undefined;
                        }}
                    }});
                }} catch (e) {{
                    el.elements = {{ get: function(name) {{ return document.getElementById(name); }} }};
                }}
            }}
            this._cache[id] = el;
        }}
        return this._cache[id];
    }}
}};
window.document = document;
document.defaultView = window;
function setTimeout(cb, delay) {{ return cb(); }}
function clearTimeout() {{}}
var atob = function(str) {{
    if (typeof Buffer !== "undefined") {{
        return Buffer.from(str, "base64").toString("binary");
    }}
    return str;
}};
var btoa = function(str) {{
    if (typeof Buffer !== "undefined") {{
        return Buffer.from(str, "binary").toString("base64");
    }}
    return str;
}};
"#,
            host = host
        )
    }

    fn read_answer(&self, context: &mut Context) -> InterpreterResult<String> {
        let answer = context
            .eval(Source::from_bytes("__state.getValue('jschl_answer');"))
            .map_err(|err| InterpreterError::Execution(err.to_string()))?;

        if answer.is_null() || answer.is_undefined() {
            return Err(InterpreterError::Execution(
                "jschl_answer not set by script".into(),
            ));
        }

        if let Ok(number) = answer.to_number(context)
            && number.is_finite()
        {
            return Ok(format!("{number:.10}", number = number));
        }

        let text = answer
            .to_string(context)
            .map_err(|err| InterpreterError::Execution(err.to_string()))?
            .to_std_string()
            .map_err(|_| InterpreterError::Other("unable to convert interpreter output".into()))?;

        Ok(text)
    }
}

impl JavascriptInterpreter for BoaJavascriptInterpreter {
    fn solve_challenge(&self, page_html: &str, host: &str) -> InterpreterResult<String> {
        let scripts = self.extract_scripts(page_html);
        if scripts.is_empty() {
            return Err(InterpreterError::Execution(
                "no <script> tags found in challenge page".into(),
            ));
        }

        let mut context = Context::default();
        let prelude = self.build_prelude(host);

        context
            .eval(Source::from_bytes(&prelude))
            .map_err(|err| InterpreterError::Other(err.to_string()))?;

        let mut executed_any = false;
        for script in scripts {
            if script.trim().is_empty() {
                continue;
            }
            executed_any = true;
            context
                .eval(Source::from_bytes(script))
                .map_err(|err| InterpreterError::Execution(err.to_string()))?;
        }

        if !executed_any {
            return Err(InterpreterError::Execution(
                "challenge page does not contain executable JavaScript".into(),
            ));
        }

        self.read_answer(&mut context)
    }

    fn execute(&self, script: &str, host: &str) -> InterpreterResult<String> {
        let mut context = Context::default();
        let prelude = self.build_prelude(host);

        context
            .eval(Source::from_bytes(&prelude))
            .map_err(|err| InterpreterError::Other(err.to_string()))?;

        let result = context
            .eval(Source::from_bytes(script))
            .map_err(|err| InterpreterError::Execution(err.to_string()))?;

        let text = result
            .to_string(&mut context)
            .map_err(|err| InterpreterError::Execution(err.to_string()))?
            .to_std_string()
            .map_err(|_| InterpreterError::Other("unable to convert interpreter output".into()))?;

        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solves_basic_challenge() {
        let html = r#"
        <html>
        <body>
            <form id="challenge-form">
                <input type="hidden" id="jschl_answer" />
            </form>
            <script>
                setTimeout(function(){
                    var a = 10;
                    var b = 5;
                    document.getElementById('jschl_answer').value = a + b;
                }, 4000);
            </script>
        </body>
        </html>
        "#;

        let interpreter = BoaJavascriptInterpreter::new();
        let answer = interpreter.solve_challenge(html, "example.com").unwrap();
        assert_eq!(answer, "15.0000000000");
    }

    #[test]
    fn error_when_missing_script() {
        let html = "<html><body>No script</body></html>";
        let interpreter = BoaJavascriptInterpreter::new();
        let err = interpreter
            .solve_challenge(html, "example.com")
            .unwrap_err();
        assert!(matches!(err, InterpreterError::Execution(_)));
    }
}
