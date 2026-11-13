use crate::{helpers::create_request_get, settings};
use aidoku::{
	HashMap, Result,
	alloc::{string::String, string::ToString, vec::Vec},
	helpers::uri::QueryParameters,
	imports::{
		js::WebView,
		net::Response,
		std::{current_date, sleep},
	},
	prelude::*,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

const INSTALLER_REQUEST_TOKEN: &str = "__AIDOKU_INSTALLER_REQUEST_TOKEN__";
const INSTALLER_RESPONSE_TOKEN: &str = "__AIDOKU_INSTALLER_RESPONSE_TOKEN__";

const CF_CHALLENGE_HTML_ERROR_MESSAGE: &str = "Response returned CF challenge page. If problem persist, please clear the source cache and restart the application to resolve this issue.";
const CF_CHALLENGE_ERROR_MESSAGE: &str = "Response returned CF challenge page instead of JSON data. If problem persist, please clear the source cache and restart the application to resolve this issue.";

const WAF_CHALLENGE_KEY: &str = "captcha_required";
const WAF_CHALLENGE_HTML_ERROR_MESSAGE: &str = "Response returned WAF challenge page. Please open Comix Settings and Verify Captcha to resolve this issue.";
const WAF_CHALLENGE_ERROR_MESSAGE: &str = "Response returned WAF challenge page instead of JSON data. Please open Comix Settings and Verify Captcha to resolve this issue.";

const CHAPTER_LIST_INTERVAL_SECS: i64 = 3;
const SERVER_ERROR_CODES: &[u16] = &[502, 503, 522, 523];
const SERVER_ERROR_RETRIES: usize = 2;
const SERVER_ERROR_RETRY_SECS: i32 = 2;

#[derive(Deserialize)]
struct FetchResult {
	status: u16,
	cf: Option<String>,
	server: Option<String>,
	detail: Option<String>,
	data: Option<Value>,
}

impl FetchResult {
	fn is_waf_challenge(&self) -> bool {
		self.status == 403
			&& self
				.data
				.as_ref()
				.and_then(|data| data.get("error"))
				.and_then(Value::as_str)
				== Some(WAF_CHALLENGE_KEY)
	}
}

#[derive(Deserialize)]
struct AxiosRequest {
	url: String,
	params: Option<HashMap<String, Value>>,
}

pub struct ComixWebView {
	web_view: WebView,
	// mirror the webview was loaded from, reloaded when the setting changes
	initialized_url: Option<String>,
	next_chapter_list_at: i64,
}

impl ComixWebView {
	pub fn new() -> Self {
		Self {
			web_view: WebView::new(),
			initialized_url: None,
			next_chapter_list_at: 0,
		}
	}

	fn ensure_loaded(&mut self) -> Result<()> {
		let base_url = settings::base_url();
		if self.initialized_url.as_deref() != Some(base_url.as_str()) {
			self.load_webview(&base_url)?;
		}
		Ok(())
	}

	fn load_webview(&mut self, base_url: &str) -> Result<()> {
		let request = create_request_get(base_url)?;
		let response = request.send()?;

		let status_code = response.status_code();

		if status_code == 403
			&& response
				.get_header("cf-mitigated")
				.is_some_and(|value| value == "challenge")
		{
			bail!("{CF_CHALLENGE_HTML_ERROR_MESSAGE}")
		} else if status_code >= 400 {
			bail!("{}", describe_error(&response))
		} else if response
			.get_html()?
			.select_first("head > title")
			.is_some_and(|e| e.text().is_some_and(|t| t == "Security check"))
		{
			bail!("{}", WAF_CHALLENGE_HTML_ERROR_MESSAGE)
		}

		self.web_view
			.load_html_blocking(response.get_string()?.as_str(), Some(base_url))?;
		self.find_functions(base_url, &response)?;
		self.initialized_url = Some(base_url.into());
		Ok(())
	}

	fn find_functions(&mut self, base_url: &str, response: &Response) -> Result<()> {
		let main_module_src = response
			.get_html()?
			.select_first("head > script[type=\"module\"][src*=\"main\"]")
			.and_then(|e| e.attr("src"))
			.ok_or_else(|| error!("Main module not found"))?;
		let main_module_url = Self::module_url(base_url, &main_module_src)?;
		let main_module = create_request_get(&main_module_url)?.string()?;
		let api_module = main_module
			.split(['\'', '"'])
			.find(|path| {
				path.strip_prefix("./")
					.unwrap_or(path)
					.starts_with("apicore-")
					&& path.ends_with(".js")
			})
			.ok_or_else(|| error!("API module not found"))?;
		let api_module_url = Self::module_url(&main_module_url, api_module)?;
		let source = create_request_get(&api_module_url)?.string()?;
		let module_body = Self::load_module_body(&api_module_url, &source, 0)?;

		let names: Vec<&str> = {
			let words: Vec<&str> = source
				.split(|c: char| !c.is_ascii() || !Self::is_identifier_byte(c as u8))
				.filter(|s| !s.is_empty())
				.collect();
			let mut names: Vec<&str> = words
				.windows(2)
				.filter(|pair| {
					matches!(pair[0], "var" | "let" | "const") && Self::is_identifier(pair[1])
				})
				.map(|pair| pair[1])
				.collect();
			names.sort_unstable();
			names.dedup();
			names
		};
		let names = serde_json::to_string(&names)?;
		let result = self
			.web_view
			.eval(&format!(
				"(() => {{
				try {{
					{module_body}
					for (const name of {names}) {{
						try {{
							const client = eval(name);
							const requests = client?.interceptors?.request?.handlers;
							const responses = client?.interceptors?.response?.handlers;
							if (!requests?.length || !responses?.length) continue;
							const request = requests[requests.length - 1]?.fulfilled;
							const response = responses[responses.length - 1]?.fulfilled;
							if (typeof request !== 'function' || typeof response !== 'function') continue;
							window['{INSTALLER_REQUEST_TOKEN}'] = request;
							window['{INSTALLER_RESPONSE_TOKEN}'] = response;
							return 'ok';
						}} catch (e) {{}}
					}}
					return 'API interceptors not found';
				}} catch (e) {{
					return 'JS error: ' + e;
				}}
			}})()"
			))
			.map_err(|e| error!("Failed to load API client: {e:?}"))?;
		if result != "ok" {
			bail!("Failed to load API client: {result}");
		}
		Ok(())
	}

	fn module_url(base: &str, path: &str) -> Result<String> {
		if path.starts_with("https://") {
			return Ok(path.into());
		}
		if path.starts_with('/') {
			// origin of `base`, i.e. everything before the first path slash
			let origin_end = base
				.get("https://".len()..)
				.and_then(|rest| rest.find('/'))
				.map_or(base.len(), |i| i + "https://".len());
			return Ok(format!("{}{path}", &base[..origin_end]));
		}
		let path = path.strip_prefix("./").unwrap_or(path);
		let directory = base
			.rsplit_once('/')
			.filter(|(dir, _)| dir.len() > "https://".len());
		Ok(format!(
			"{}/{}",
			directory.map_or(base, |(dir, _)| dir),
			path
		))
	}

	fn load_module_body(url: &str, source: &str, depth: usize) -> Result<String> {
		if depth > 4 {
			bail!("API module dependency limit exceeded");
		}
		let (body, _) = Self::split_module(source)?;

		let mut result = String::new();
		let mut offset = 0;

		let keyword = "import";
		let keyword_positions = body.match_indices(keyword).filter_map(move |(start, _)| {
			let end = start + keyword.len();
			let before = start.checked_sub(1).map(|i| body.as_bytes()[i]);
			let after = body.as_bytes().get(end).copied();
			(!before.is_some_and(Self::is_identifier_byte)
				&& !after.is_some_and(Self::is_identifier_byte))
			.then_some(start)
		});

		for start in keyword_positions {
			let Some(rest) = body[start + keyword.len()..].trim_start().strip_prefix('{') else {
				continue;
			};
			let (bindings, rest) = rest
				.split_once('}')
				.ok_or_else(|| error!("Invalid API module import"))?;
			let rest = rest
				.trim_start()
				.strip_prefix("from")
				.ok_or_else(|| error!("Invalid API module import"))?
				.trim_start();
			let quote = rest
				.chars()
				.next()
				.filter(|c| matches!(c, '\'' | '"'))
				.ok_or_else(|| error!("Invalid API module import path"))?;
			let (path, rest) = rest[1..]
				.split_once(quote)
				.ok_or_else(|| error!("Invalid API module import path"))?;
			result.push_str(&body[offset..start]);
			offset = body.len() - rest.len();
			let dependency_url = Self::module_url(url, path)?;
			let dependency = create_request_get(&dependency_url)?.string()?;
			let (_, exports) = Self::split_module(&dependency)?;
			let dependency_body = Self::load_module_body(&dependency_url, &dependency, depth + 1)?;
			let bindings = Self::module_bindings(bindings, true)?;
			let exports = Self::module_bindings(exports, false)?;
			result.push_str(&format!(
				"const {{{bindings}}} = (() => {{{dependency_body}; return {{{exports}}};}})();"
			));
		}
		result.push_str(&body[offset..]);
		Ok(result)
	}

	fn split_module(source: &str) -> Result<(&str, &str)> {
		let (body, exports) = source
			.rsplit_once("export")
			.ok_or_else(|| error!("API module exports not found"))?;
		let exports = exports.trim().trim_end_matches(';').trim_end();
		let exports = exports
			.strip_prefix('{')
			.and_then(|s| s.strip_suffix('}'))
			.filter(|s| !s.contains(['{', '}']))
			.ok_or_else(|| error!("API module exports not found"))?;
		Ok((body, exports))
	}

	fn module_bindings(bindings: &str, import: bool) -> Result<String> {
		let mut result = Vec::new();
		for binding in bindings.split(',').map(str::trim).filter(|s| !s.is_empty()) {
			let parts: Vec<&str> = binding.split_whitespace().collect();
			let (local, exported) = match parts.as_slice() {
				[name] => (*name, *name),
				[name, "as", alias] => (*name, *alias),
				_ => bail!("Unsupported API module binding"),
			};
			if !Self::is_identifier(local) || !Self::is_identifier(exported) {
				bail!("Invalid API module binding");
			}
			result.push(if import {
				format!("{local}:{exported}")
			} else {
				format!("{exported}:{local}")
			});
		}
		Ok(result.join(","))
	}

	fn is_identifier_byte(byte: u8) -> bool {
		byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
	}

	fn is_identifier(name: &str) -> bool {
		!name.is_empty()
			&& !name.as_bytes()[0].is_ascii_digit()
			&& name.bytes().all(Self::is_identifier_byte)
	}

	/// Runs the site's request interceptor on `url`, returning the axios config as json,
	/// `missing` when the interceptor isn't installed, or `error: ...` when it throws.
	fn sign_request(
		&self,
		url: &str,
	) -> core::result::Result<String, aidoku::imports::js::JsError> {
		self.web_view.eval(&format!(
			"(() => {{
			if (typeof window['{INSTALLER_REQUEST_TOKEN}'] !== 'function') {{
				return 'missing';
			}}
			try {{
			const url = new URL('{url}');
			const result = {{}};

			for (const [key, rawValue] of url.searchParams) {{
				const value = rawValue.length > 0 && [...rawValue].every(c => c >= '0' && c <= '9')
					? Number(rawValue)
					: rawValue;

				const parts = key.split(']').join('').split('[');

				let current = result;

				for (let i = 0; i < parts.length; i++) {{
					const part = parts[i];
					const last = i === parts.length - 1;

					if (last) {{
						if (part === '') {{
							current.push(value);
						}} else if (current[part] === undefined) {{
							current[part] = value;
						}} else if (Array.isArray(current[part])) {{
							current[part].push(value);
						}} else {{
							current[part] = [current[part], value];
						}}
					}} else {{
						const nextPart = parts[i + 1];

						current[part] ??= nextPart === '' ? [] : {{}};
						current = current[part];
					}}
				}}
			}}

			const request = window['{INSTALLER_REQUEST_TOKEN}']({{
				url: `${{url.origin}}${{url.pathname}}`,
				method: 'GET',
				params: result,
			}});

			return JSON.stringify(request);
			}} catch (e) {{
				return 'error: ' + e;
			}}
		}})()"
		))
	}

	/// Signs `url` with the site's request interceptor, returning the url to request.
	fn sign_url(&mut self, url: &str) -> Result<String> {
		self.ensure_loaded()?;

		// the webview can lose its state (e.g. a reload), so set it up again once if needed
		let result = match self.sign_request(url) {
			Ok(result) if result != "missing" => result,
			_ => {
				self.initialized_url = None;
				self.ensure_loaded()?;
				self.sign_request(url)
					.map_err(|e| error!("Failed to sign request: {e:?}"))?
			}
		};
		if result == "missing" {
			bail!("Request signer missing after reloading the webview");
		}
		if let Some(error) = result.strip_prefix("error: ") {
			bail!("Failed to sign request: {error}");
		}

		let axios_request: AxiosRequest = serde_json::from_str(result.as_str())?;

		fn build_query(params_map: &HashMap<String, Value>) -> QueryParameters {
			let mut params = QueryParameters::new();

			for (key, value) in params_map {
				push_value(&mut params, key, value);
			}

			params
		}

		fn push_value(params: &mut QueryParameters, key: &str, value: &Value) {
			match value {
				Value::Null => {
					params.push_key(key);
				}

				Value::Bool(_) | Value::Number(_) | Value::String(_) => {
					let value_str = value.to_string();

					// Remove JSON string quotes
					let value_str = match value {
						Value::String(s) => s.as_str(),
						_ => value_str.as_str(),
					};

					params.push(key, Some(value_str));
				}

				Value::Array(arr) => {
					let array_key = format!("{key}[]");

					for item in arr {
						match item {
							Value::String(s) => {
								params.push(&array_key, Some(s));
							}
							_ => {
								let value_str = item.to_string();
								params.push(&array_key, Some(&value_str));
							}
						}
					}
				}

				Value::Object(obj) => {
					for (child_key, child_value) in obj {
						let nested_key = format!("{key}[{child_key}]");
						push_value(params, &nested_key, child_value);
					}
				}
			}
		}

		if let Some(params) = axios_request.params {
			let query = build_query(&params);
			Ok(format!("{}?{query}", axios_request.url))
		} else {
			Ok(axios_request.url)
		}
	}

	/// Waits until the next chapter list request is allowed, as the site blocks clients
	/// that page through chapter lists too quickly (e.g. during library refreshes).
	pub fn pace_chapter_list(&mut self) {
		let now = current_date();
		let wait = self.next_chapter_list_at - now;
		if wait > 0 {
			sleep(wait as i32);
		}
		self.next_chapter_list_at = now.max(self.next_chapter_list_at) + CHAPTER_LIST_INTERVAL_SECS;
	}

	/// Requests `url` from inside the webview, like the site itself does, and returns the
	/// decoded json. Requests made outside of it get answered with 502s by the site.
	pub fn fetch_json<T>(&mut self, url: &str) -> Result<T>
	where
		T: DeserializeOwned,
	{
		let fetched = self.fetch(url)?;
		if fetched.status == 403 && fetched.cf.as_deref() == Some("challenge") {
			bail!("{CF_CHALLENGE_ERROR_MESSAGE}")
		} else if fetched.is_waf_challenge() {
			bail!("{WAF_CHALLENGE_ERROR_MESSAGE}")
		} else if !(200..300).contains(&fetched.status) {
			bail!(
				"Response Error: {} (server: {}, {})",
				fetched.status,
				fetched.server.as_deref().unwrap_or("unknown"),
				fetched.detail.as_deref().unwrap_or_default()
			)
		}

		serde_json::from_value(fetched.data.unwrap_or_default())
			.map_err(|e| error!("Invalid json: {}", e))
	}

	/// Whether the site still asks for its captcha, checked with a small chapter list request
	/// as the captcha guards chapters and not the home page.
	pub fn needs_captcha(&mut self) -> bool {
		let url = format!("{}/manga/pvry/chapters?limit=1", settings::api_url());
		self.fetch(&url)
			.is_ok_and(|fetched| fetched.is_waf_challenge())
	}

	fn fetch(&mut self, url: &str) -> Result<FetchResult> {
		let mut attempt = 0;
		loop {
			let signed_url = self.sign_url(url)?;
			let result = self
				.web_view
				.eval(&format!(
					"(() => {{
					try {{
						const xhr = new XMLHttpRequest();
						xhr.open('GET', {url}, false);
						xhr.setRequestHeader('Accept', 'application/json, text/plain, */*');
						// the site raises this when it thinks requests are automated
						xhr.setRequestHeader('X-Rt', '0');
						xhr.send();
						const result = {{
							status: xhr.status,
							cf: xhr.getResponseHeader('cf-mitigated'),
							server: xhr.getResponseHeader('server'),
						}};
						try {{
							result.data = JSON.parse(xhr.responseText);
						}} catch (e) {{
							const title = /<title>([^<]*)/i.exec(xhr.responseText);
							result.detail = (title ? title[1] : xhr.responseText.slice(0, 100)).trim();
						}}
						const enc = xhr.getResponseHeader('x-enc');
						if (enc && result.data && xhr.status === 200) {{
							const decoded = window['{INSTALLER_RESPONSE_TOKEN}']({{
								data: result.data,
								status: 200,
								headers: {{ 'x-enc': enc }},
							}});
							result.data = {{ result: decoded && decoded.data }};
						}}
						return JSON.stringify(result);
					}} catch (e) {{
						return JSON.stringify({{ status: 0, detail: 'error: ' + e }});
					}}
				}})()",
					url = serde_json::to_string(&signed_url)?,
				))
				.map_err(|e| error!("Failed to request {url}: {e:?}"))?;
			let fetched: FetchResult = serde_json::from_str(&result)?;

			if SERVER_ERROR_CODES.contains(&fetched.status) && attempt < SERVER_ERROR_RETRIES {
				attempt += 1;
				sleep(SERVER_ERROR_RETRY_SECS);
				continue;
			}
			return Ok(fetched);
		}
	}
}

/// Error message for a failed response, noting who answered and what they said so
/// gateway errors from cloudflare can be told apart from ones from the site itself
fn describe_error(response: &Response) -> String {
	let server = response
		.get_header("server")
		.unwrap_or_else(|| "unknown".into());
	let body = response.get_string().unwrap_or_default();
	let detail = match (body.find("<title>"), body.find("</title>")) {
		(Some(start), Some(end)) if start < end => &body[start + 7..end],
		_ => body
			.get(..body.floor_char_boundary(100))
			.unwrap_or_default(),
	};
	let detail = detail.split_whitespace().collect::<Vec<_>>().join(" ");
	format!(
		"Response Error: {} (server: {server}, {detail})",
		response.status_code()
	)
}
