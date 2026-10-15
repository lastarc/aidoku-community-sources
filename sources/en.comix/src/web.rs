// reference: https://github.com/nobottomline/extensions-source/blob/c8fe930f315f3baee23587559edfceab5e969202/src/en/comix/src/eu/kanade/tachiyomi/extension/en/comix/Signer.kt
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
use regex::Regex;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

const GET_VMOBJ_JS: &str = "\
const vmKey = Object.keys(window).find(key => key.startsWith('vm'));\
const vmObj = window[vmKey];\
if (!vmObj || typeof vmObj !== 'object' || vmObj === window) {\
	return '';\
}";

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
		if self.find_functions().is_err() {
			self.find_secure_module_src(base_url, &response)?;
			self.find_functions()?;
		}
		self.initialized_url = Some(base_url.into());
		Ok(())
	}

	fn find_secure_module_src(&mut self, base_url: &str, response: &Response) -> Result<()> {
		let main_module_src = response
			.get_html()?
			.select("head > script[type=\"module\"][src*=\"main\"]")
			.and_then(|e| e.first())
			.and_then(|e| e.attr("src"))
			.ok_or(error!("Main module not found"))?;
		if let Some(js_asset_path_index) = main_module_src.rfind("/") {
			let js_asset_path = &main_module_src[0..js_asset_path_index + 1];
			let secure_script_regex = Regex::new("(secure-[A-Za-z0-9-_]+?\\.js)").unwrap();
			let main_module_contents =
				create_request_get(&format!("{base_url}{main_module_src}"))?.string()?;
			if let Some(secure_script_path) = secure_script_regex
				.captures(main_module_contents.as_str())
				.and_then(|captures| captures.get(1).map(|m| m.as_str()))
			{
				let secure_module_contents =
					create_request_get(&format!("{base_url}{js_asset_path}{secure_script_path}"))?
						.string()?;
				let Some(module_body) = secure_module_contents
					.rfind("export")
					.filter(|&index| {
						secure_module_contents[index + "export".len()..]
							.trim_start()
							.starts_with('{')
					})
					.map(|index| &secure_module_contents[..index])
				else {
					bail!("Secure module exports not found");
				};
				let result = self
					.web_view
					.eval(&format!(
						"(() => {{
						try {{
							{module_body}
							return 'ok';
						}} catch (e) {{
							return 'error: ' + e;
						}}
					}})()"
					))
					.map_err(|e| error!("Failed to load secure module: {e:?}"))?;
				if result != "ok" {
					bail!("Failed to load secure module: {result}");
				}
				Ok(())
			} else {
				bail!("Secure module not found");
			}
		} else {
			bail!("Invalid path")
		}
	}

	fn find_functions(&mut self) -> Result<()> {
		let result = self
			.web_view
			.eval(&format!(
				"(() => {{
			try {{
				{GET_VMOBJ_JS}
				let fnames = Object.keys(vmObj);
				let inst = '';
				for (let j = 0; j < fnames.length; j++) {{
					let fn = vmObj[fnames[j]];
					if (typeof fn !== 'function') continue;
					let ref = 'window[' + JSON.stringify(vmKey) + '].' + fnames[j];
					if (!inst) {{
						try {{
							let got = false;
							fn({{
								interceptors: {{
									request: {{ use: function() {{ got = true; }} }},
									response: {{ use: function() {{ got = true; }} }}
								}}
							}});
							if (got) {{
								inst = ref;
								fn({{
									interceptors: {{
										request: {{
											use: function (fn) {{ window['{INSTALLER_REQUEST_TOKEN}'] = fn; }},
										}},
										response: {{
											use: function (fn) {{ window['{INSTALLER_RESPONSE_TOKEN}'] = fn; }},
										}},
									}}
								}});
							}}
						}} catch (e) {{}}
					}}

				}}
				return inst;
			}} catch (e) {{}}
			return '';
		}})()",
			))
			.map_err(|e| error!("Failed to find installer function: {e:?}"))?;
		let expr: Vec<&str> = result.split("||").collect();
		if expr.is_empty() || expr[0].is_empty() {
			bail!("Failed to find installer function");
		}
		Ok(())
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
				const value = /^\\d+$/.test(rawValue)
					? Number(rawValue)
					: rawValue;

				const parts = key.replace(/\\]/g, '').split('[');

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
