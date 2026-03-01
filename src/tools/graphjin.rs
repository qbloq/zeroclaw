use super::traits::{Tool, ToolResult};
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// GraphJin database query tool.
///
/// Connects to a running GraphJin service to provide schema discovery and
/// GraphQL query execution. GraphJin auto-discovers database schema, resolves
/// relationships via foreign keys, and compiles GraphQL to optimised SQL.
///
/// Supported actions:
/// - `list_tables`    — list all tables/views/functions available
/// - `describe_table` — show columns, types, and relationships for a table
/// - `query`          — execute a read-only GraphQL query
/// - `mutate`         — execute a GraphQL mutation (requires `allow_mutations = true`)
pub struct GraphJinTool {
    api_url: String,
    timeout_secs: u64,
    max_response_size: usize,
    allow_mutations: bool,
    security: Arc<SecurityPolicy>,
}

impl GraphJinTool {
    pub fn new(
        security: Arc<SecurityPolicy>,
        api_url: String,
        timeout_secs: u64,
        max_response_size: usize,
        allow_mutations: bool,
    ) -> Self {
        Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            timeout_secs: timeout_secs.max(1),
            max_response_size,
            allow_mutations,
            security,
        }
    }

    fn graphql_url(&self) -> String {
        let path = "/api/v1/graphql";
        if self.api_url.contains(path) {
            self.api_url.clone()
        } else {
            format!("{}{}", self.api_url, path)
        }
    }

    fn build_client(&self) -> anyhow::Result<reqwest::Client> {
        let timeout = if self.timeout_secs == 0 {
            tracing::warn!("graphjin: timeout_secs is 0, using 30s default");
            30
        } else {
            self.timeout_secs
        };

        let builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .connect_timeout(Duration::from_secs(10));

        Ok(builder.build()?)
    }

    fn truncate(&self, text: String) -> String {
        if text.len() > self.max_response_size {
            let mut t: String = text.chars().take(self.max_response_size).collect();
            t.push_str("\n\n... [Response truncated due to size limit] ...");
            t
        } else {
            text
        }
    }

    /// POST a GraphQL document to GraphJin and return the body text.
    async fn post_graphql(
        &self,
        client: &reqwest::Client,
        query: &str,
        variables: Option<&serde_json::Value>,
    ) -> anyhow::Result<String> {
        let mut payload = json!({ "query": query });
        if let Some(vars) = variables {
            if !vars.is_null() {
                payload["variables"] = vars.clone();
            }
        }

        let response = client
            .post(self.graphql_url())
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("User-Agent", "ZeroClaw/1.0")
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await?;

        if !status.is_success() {
            anyhow::bail!("GraphJin returned HTTP {}: {}", status.as_u16(), body);
        }

        Ok(body)
    }

    async fn action_list_tables(&self) -> anyhow::Result<ToolResult> {
        let client = self.build_client()?;

        // Use GraphQL introspection to list all query-root types (tables/views).
        // GraphJin exposes every table as a top-level query field.
        let introspection = r#"
query IntrospectionQuery {
  __schema {
    queryType {
      fields {
        name
        description
        args {
          name
          type { name kind ofType { name kind } }
        }
      }
    }
  }
}
"#;

        match self.post_graphql(&client, introspection, None).await {
            Ok(body) => {
                let truncated = self.truncate(body);
                // Parse the JSON and reformat it into a readable table list
                let output = match serde_json::from_str::<serde_json::Value>(&truncated) {
                    Ok(json) => format_table_list(&json),
                    Err(_) => truncated,
                };

                Ok(ToolResult {
                    success: true,
                    output,
                    error: None,
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Failed to connect to GraphJin at {}: {}. \
                     Make sure GraphJin is running (graphjin serve) and [graphjin].api_url is correct.",
                    self.api_url, e
                )),
            }),
        }
    }

    async fn action_describe_table(&self, table: &str) -> anyhow::Result<ToolResult> {
        let client = self.build_client()?;

        // Use GraphQL introspection to inspect the concrete type returned by this table.
        // GraphJin names return types as "<table>_row" or similar.
        let query = format!(
            r#"
query IntrospectionQuery {{
  __type(name: "{table}") {{
    name
    kind
    description
    fields {{
      name
      description
      type {{
        name
        kind
        ofType {{ name kind }}
      }}
    }}
  }}
}}
"#,
            table = table
        );

        match self.post_graphql(&client, &query, None).await {
            Ok(body) => {
                let truncated = self.truncate(body);
                Ok(ToolResult {
                    success: true,
                    output: truncated,
                    error: None,
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Failed to describe table '{}': {}", table, e)),
            }),
        }
    }

    async fn action_query(
        &self,
        graphql: &str,
        variables: Option<&serde_json::Value>,
    ) -> anyhow::Result<ToolResult> {
        let client = self.build_client()?;

        match self.post_graphql(&client, graphql, variables).await {
            Ok(body) => {
                let truncated = self.truncate(body);
                Ok(ToolResult {
                    success: true,
                    output: truncated,
                    error: None,
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("GraphQL query failed: {}", e)),
            }),
        }
    }

    async fn action_mutate(
        &self,
        graphql: &str,
        variables: Option<&serde_json::Value>,
    ) -> anyhow::Result<ToolResult> {
        if !self.allow_mutations {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(
                    "Mutations are disabled. Set [graphjin].allow_mutations = true in config.toml \
                     to enable insert/update/delete operations."
                        .into(),
                ),
            });
        }

        if !self.security.can_act() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Action blocked: autonomy is read-only".into()),
            });
        }

        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Action blocked: rate limit exceeded".into()),
            });
        }

        let client = self.build_client()?;

        match self.post_graphql(&client, graphql, variables).await {
            Ok(body) => {
                let truncated = self.truncate(body);
                Ok(ToolResult {
                    success: true,
                    output: truncated,
                    error: None,
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("GraphQL mutation failed: {}", e)),
            }),
        }
    }
}

/// Reformat the introspection JSON into a human-readable table list.
fn format_table_list(json: &serde_json::Value) -> String {
    let fields = json
        .pointer("/data/__schema/queryType/fields")
        .and_then(|v| v.as_array());

    let Some(fields) = fields else {
        // Return raw JSON if introspection structure is unexpected
        return serde_json::to_string_pretty(json).unwrap_or_default();
    };

    if fields.is_empty() {
        return "No tables found. Make sure GraphJin is connected to a database.".into();
    }

    let mut lines = vec![format!("Available tables/views ({} total):", fields.len())];
    for field in fields {
        let name = field.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let desc = field
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Skip internal cursor fields (e.g. products_cursor)
        if name.ends_with("_cursor") {
            continue;
        }

        if desc.is_empty() {
            lines.push(format!("  - {name}"));
        } else {
            lines.push(format!("  - {name}: {desc}"));
        }
    }

    lines.join("\n")
}

#[async_trait]
impl Tool for GraphJinTool {
    fn name(&self) -> &str {
        "graphjin"
    }

    fn description(&self) -> &str {
        "Query databases via GraphJin — a service that converts GraphQL to optimised SQL. \
        Use `list_tables` to discover available tables, `describe_table` to see columns \
        and relationships, `query` to read data, and `mutate` to write data (if enabled). \
        \n\nGraphQL query syntax reference:\
        \n- Basic query: `{ products(limit: 5) { id name price } }`\
        \n- Filter:      `{ products(where: { price: { gt: 10 } }) { id name } }`\
        \n- Operators:   eq, neq, gt, gte, lt, lte, in, nin, iregex, is_null\
        \n- Logic:       and, or, not — e.g. `{ p(where: { and: [ {price:{gt:5}}, {price:{lt:100}} ] }) { id } }`\
        \n- Order:       `{ products(order_by: { price: desc }) { id } }`\
        \n- Pagination:  `{ products(limit: 10, offset: 20) { id } }` or cursor-based with `first`/`after`\
        \n- Relations:   `{ users { email products { name price } } }` (auto-joined via foreign keys)\
        \n- Aggregates:  `{ products { count_id sum_price avg_price max_price } }`\
        \n- Full-text:   `{ products(search: \"keyword\") { id name } }`\
        \n- Mutations:   `mutation { products(insert: { name: \"X\", price: 9.99 }) { id } }`"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list_tables", "describe_table", "query", "mutate"],
                    "description": "Action to perform. Use list_tables/describe_table for schema discovery before writing queries."
                },
                "table": {
                    "type": "string",
                    "description": "Table name to describe (required for describe_table action)"
                },
                "graphql": {
                    "type": "string",
                    "description": "GraphQL query or mutation string (required for query/mutate actions)"
                },
                "variables": {
                    "type": "object",
                    "description": "Optional variables map for the GraphQL query (e.g. {\"id\": 42})"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: action"))?;

        match action {
            "list_tables" => self.action_list_tables().await,

            "describe_table" => {
                let table = args
                    .get("table")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!("Missing required parameter: table (for describe_table)")
                    })?;
                if table.trim().is_empty() {
                    anyhow::bail!("Parameter 'table' cannot be empty");
                }
                self.action_describe_table(table).await
            }

            "query" => {
                let graphql = args.get("graphql").and_then(|v| v.as_str()).ok_or_else(|| {
                    anyhow::anyhow!("Missing required parameter: graphql (for query)")
                })?;
                if graphql.trim().is_empty() {
                    anyhow::bail!("Parameter 'graphql' cannot be empty");
                }
                let variables = args.get("variables");
                self.action_query(graphql, variables).await
            }

            "mutate" => {
                let graphql = args.get("graphql").and_then(|v| v.as_str()).ok_or_else(|| {
                    anyhow::anyhow!("Missing required parameter: graphql (for mutate)")
                })?;
                if graphql.trim().is_empty() {
                    anyhow::bail!("Parameter 'graphql' cannot be empty");
                }
                let variables = args.get("variables");
                self.action_mutate(graphql, variables).await
            }

            other => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Unknown action: '{other}'. Valid actions: list_tables, describe_table, query, mutate"
                )),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{AutonomyLevel, SecurityPolicy};

    fn test_tool() -> GraphJinTool {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            ..SecurityPolicy::default()
        });
        GraphJinTool::new(
            security,
            "http://localhost:8080".into(),
            30,
            1_000_000,
            false,
        )
    }

    fn test_tool_with_mutations() -> GraphJinTool {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            ..SecurityPolicy::default()
        });
        GraphJinTool::new(
            security,
            "http://localhost:8080".into(),
            30,
            1_000_000,
            true,
        )
    }

    #[test]
    fn tool_name_is_graphjin() {
        assert_eq!(test_tool().name(), "graphjin");
    }

    #[test]
    fn tool_description_is_nonempty() {
        let tool = test_tool();
        let desc = tool.description();
        assert!(!desc.is_empty());
        assert!(desc.contains("GraphQL"));
    }

    #[test]
    fn parameters_schema_is_valid_object() {
        let schema = test_tool().parameters_schema();
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"].is_object());
        assert!(schema["properties"]["action"].is_object());
        assert!(schema["properties"]["graphql"].is_object());
        assert!(schema["properties"]["table"].is_object());
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("action")));
    }

    #[test]
    fn api_url_strips_trailing_slash() {
        let security = Arc::new(SecurityPolicy::default());
        let tool = GraphJinTool::new(
            security,
            "http://localhost:8080/".into(),
            30,
            1_000_000,
            false,
        );
        assert_eq!(tool.api_url, "http://localhost:8080");
        assert_eq!(tool.graphql_url(), "http://localhost:8080/api/v1/graphql");
    }

    #[test]
    fn api_url_idempotent() {
        let security = Arc::new(SecurityPolicy::default());
        // Case: user provides the full endpoint URL
        let tool = GraphJinTool::new(
            security,
            "http://10.0.0.2:8001/api/v1/graphql".into(),
            30,
            1_000_000,
            false,
        );
        assert_eq!(tool.graphql_url(), "http://10.0.0.2:8001/api/v1/graphql");
    }

    #[test]
    fn truncate_within_limit() {
        let tool = test_tool();
        let text = "hello world".to_string();
        assert_eq!(tool.truncate(text.clone()), text);
    }

    #[test]
    fn truncate_over_limit() {
        let security = Arc::new(SecurityPolicy::default());
        let tool = GraphJinTool::new(security, "http://localhost:8080".into(), 30, 10, false);
        let text = "hello world this is a long string".to_string();
        let result = tool.truncate(text);
        assert!(result.len() <= 10 + 80); // limit + truncation message
        assert!(result.contains("[Response truncated"));
    }

    #[tokio::test]
    async fn execute_missing_action_returns_error() {
        let tool = test_tool();
        let result = tool.execute(json!({})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("action"));
    }

    #[tokio::test]
    async fn execute_unknown_action_returns_error_in_output() {
        let tool = test_tool();
        let result = tool.execute(json!({"action": "fly"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Unknown action"));
    }

    #[tokio::test]
    async fn execute_query_missing_graphql_returns_error() {
        let tool = test_tool();
        let result = tool.execute(json!({"action": "query"})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("graphql"));
    }

    #[tokio::test]
    async fn execute_query_empty_graphql_returns_error() {
        let tool = test_tool();
        let result = tool
            .execute(json!({"action": "query", "graphql": "   "}))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[tokio::test]
    async fn execute_describe_table_missing_table_returns_error() {
        let tool = test_tool();
        let result = tool.execute(json!({"action": "describe_table"})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("table"));
    }

    #[tokio::test]
    async fn execute_describe_table_empty_table_returns_error() {
        let tool = test_tool();
        let result = tool
            .execute(json!({"action": "describe_table", "table": ""}))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn execute_mutate_blocked_when_mutations_disabled() {
        let tool = test_tool(); // allow_mutations = false
        let result = tool
            .execute(json!({"action": "mutate", "graphql": "mutation { users(insert: {email: \"a@b.com\"}) { id } }"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("allow_mutations"));
    }

    #[tokio::test]
    async fn execute_mutate_blocked_by_readonly_security() {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        });
        let tool = GraphJinTool::new(
            security,
            "http://localhost:8080".into(),
            30,
            1_000_000,
            true,
        );
        let result = tool
            .execute(json!({"action": "mutate", "graphql": "mutation { users(insert: {email: \"a@b.com\"}) { id } }"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("read-only"));
    }

    #[tokio::test]
    async fn execute_mutate_blocked_by_rate_limit() {
        let security = Arc::new(SecurityPolicy {
            max_actions_per_hour: 0,
            ..SecurityPolicy::default()
        });
        let tool = GraphJinTool::new(
            security,
            "http://localhost:8080".into(),
            30,
            1_000_000,
            true,
        );
        let result = tool
            .execute(json!({"action": "mutate", "graphql": "mutation { users(insert: {email: \"a@b.com\"}) { id } }"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("rate limit"));
    }

    #[test]
    fn format_table_list_with_empty_fields() {
        let json = json!({"data": {"__schema": {"queryType": {"fields": []}}}});
        let result = format_table_list(&json);
        assert!(result.contains("No tables found"));
    }

    #[test]
    fn format_table_list_with_fields() {
        let json = json!({
            "data": {
                "__schema": {
                    "queryType": {
                        "fields": [
                            {"name": "products", "description": "Product catalog"},
                            {"name": "users", "description": ""},
                            {"name": "products_cursor", "description": ""}
                        ]
                    }
                }
            }
        });
        let result = format_table_list(&json);
        assert!(result.contains("products"));
        assert!(result.contains("Product catalog"));
        assert!(result.contains("users"));
        // Cursor fields should be hidden
        assert!(!result.contains("products_cursor"));
    }

    #[test]
    fn spec_roundtrip() {
        let tool = test_tool();
        let spec = tool.spec();
        assert_eq!(spec.name, "graphjin");
        assert_eq!(spec.description, tool.description());
        assert!(spec.parameters.is_object());
    }

    #[test]
    fn tool_result_success_serde() {
        let result = ToolResult {
            success: true,
            output: "ok".into(),
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ToolResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.output, "ok");
    }

    #[tokio::test]
    async fn list_tables_fails_gracefully_when_server_unreachable() {
        let security = Arc::new(SecurityPolicy::default());
        // Use a port that should have nothing listening
        let tool = GraphJinTool::new(
            security,
            "http://127.0.0.1:19999".into(),
            1, // 1 second timeout to keep test fast
            1_000_000,
            false,
        );
        let result = tool.action_list_tables().await.unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
        let err = result.error.unwrap();
        assert!(
            err.contains("127.0.0.1:19999") || err.contains("Failed to connect"),
            "expected connection error message, got: {err}"
        );
    }
}
