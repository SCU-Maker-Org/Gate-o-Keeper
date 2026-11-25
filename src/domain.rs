//! Strongly-typed domain enums backed by SQLite `TEXT` and JSON `snake_case` values.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! domain_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $variant:ident => $str_val:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
        #[sqlx(type_name = "TEXT", rename_all = "snake_case")]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $( $variant, )+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $str_val, )+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl std::str::FromStr for $name {
            type Err = ();

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $( $str_val => Ok(Self::$variant), )+
                    _ => Err(()),
                }
            }
        }
    };
}

domain_enum! {
    pub enum UserRole {
        User => "user",
        Admin => "admin",
    }
}

domain_enum! {
    pub enum UserStatus {
        Active => "active",
        Disabled => "disabled",
    }
}

domain_enum! {
    pub enum DeviceStatus {
        Online => "online",
        Kicked => "kicked",
        LoggedOut => "logged_out",
        Expired => "expired",
    }
}

domain_enum! {
    pub enum ApprovalStatus {
        Pending => "pending",
        Approved => "approved",
        Rejected => "rejected",
        Revoked => "revoked",
    }
}

domain_enum! {
    pub enum OnlineStatus {
        Online => "online",
        Offline => "offline",
    }
}

domain_enum! {
    pub enum DoorState {
        Locked => "locked",
        Unlocked => "unlocked",
        Unknown => "unknown",
    }
}

domain_enum! {
    pub enum AuditActorType {
        User => "user",
        Admin => "admin",
        Adapter => "adapter",
        System => "system",
    }
}

domain_enum! {
    pub enum AuditResult {
        Success => "success",
        Failed => "failed",
        Timeout => "timeout",
        Denied => "denied",
    }
}

domain_enum! {
    pub enum UnlockStatus {
        Success => "success",
        Failed => "failed",
        Timeout => "timeout",
    }
}
