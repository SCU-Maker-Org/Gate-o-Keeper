use crate::error::{AppError, AppResult};
use crate::state::AppState;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AuthentikGroupSummary {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthentikApiUser {
    pub pk: serde_json::Value,
    pub uid: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub username: String,
    pub is_active: bool,
    #[serde(default)]
    pub groups_obj: Vec<AuthentikGroupSummary>,
}

impl AuthentikApiUser {
    /// Authentik primary key rendered as a string (it is an integer in the API).
    pub fn pk_string(&self) -> Option<String> {
        match &self.pk {
            serde_json::Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }

    pub fn display_name(&self) -> &str {
        if !self.name.trim().is_empty() {
            self.name.trim()
        } else if !self.username.trim().is_empty() {
            self.username.trim()
        } else {
            &self.uid
        }
    }

    pub fn group_names(&self) -> Vec<String> {
        self.groups_obj.iter().map(|g| g.name.clone()).collect()
    }
}

#[derive(Debug, Deserialize)]
struct AuthentikPagination {
    #[serde(default)]
    next: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AuthentikUserListPage {
    #[serde(default)]
    pagination: Option<AuthentikPagination>,
    #[serde(default)]
    results: Vec<AuthentikApiUser>,
}

/// Fetches a single user record by primary key from Authentik's Core API.
pub async fn fetch_authentik_user_by_pk(
    state: &AppState,
    pk: &str,
) -> AppResult<Option<AuthentikApiUser>> {
    let clean_pk = pk.trim();
    if clean_pk.is_empty()
        || !clean_pk
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(AppError::invalid("invalid Authentik user pk"));
    }
    let token = &state.config.authentik_api_token;
    let url = format!(
        "{}/api/v3/core/users/{}/",
        state.config.authentik_api_base_url, clean_pk
    );
    let resp = state
        .http
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|err| AppError::internal(format!("Authentik API request failed: {err}")))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(AppError::internal(format!(
            "Authentik user API returned status {}",
            resp.status()
        )));
    }
    let user: AuthentikApiUser = resp
        .json()
        .await
        .map_err(|err| AppError::internal(format!("invalid Authentik user JSON: {err}")))?;
    Ok(Some(user))
}

/// Fetches all user records from Authentik's Core API across paginated pages.
pub async fn fetch_authentik_users_list(state: &AppState) -> AppResult<Vec<AuthentikApiUser>> {
    const MAX_PAGES: u64 = 100;
    let token = &state.config.authentik_api_token;
    let mut all_users = Vec::new();
    let mut page_num: u64 = 1;

    loop {
        if page_num > MAX_PAGES {
            tracing::warn!(
                max_pages = MAX_PAGES,
                "Authentik users list pagination capped"
            );
            break;
        }
        let url = format!(
            "{}/api/v3/core/users/?page={}&page_size=200",
            state.config.authentik_api_base_url, page_num
        );
        let resp = state
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| AppError::internal(format!("Authentik API request failed: {err}")))?;
        if !resp.status().is_success() {
            return Err(AppError::internal(format!(
                "Authentik users API returned status {}",
                resp.status()
            )));
        }
        let page: AuthentikUserListPage = resp
            .json()
            .await
            .map_err(|err| AppError::internal(format!("invalid Authentik users JSON: {err}")))?;

        let results_empty = page.results.is_empty();
        all_users.extend(page.results);

        match page
            .pagination
            .and_then(|p| p.next)
            .filter(|&n| n > page_num)
        {
            Some(next_page) if !results_empty => page_num = next_page,
            _ => break,
        }
    }

    Ok(all_users)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentik_api_user_requires_is_active() {
        let missing = serde_json::json!({
            "pk": 1,
            "uid": "u-1",
            "username": "alice"
        });
        assert!(serde_json::from_value::<AuthentikApiUser>(missing).is_err());

        let disabled = serde_json::json!({
            "pk": 1,
            "uid": "u-1",
            "username": "alice",
            "is_active": false
        });
        let parsed: AuthentikApiUser = serde_json::from_value(disabled).unwrap();
        assert!(!parsed.is_active);
    }
}
