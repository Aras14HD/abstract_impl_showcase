mod traits {
    use abstract_impl::abstract_impl;
    use thiserror::Error;
    pub trait TimeType {
        type Time;
    }
    #[abstract_impl(no_dummy)]
    impl TimeUsingType<T> for TimeType {
        type Time = T;
    }
    pub trait AuthTokenType {
        type AuthToken;
    }
    #[abstract_impl(no_dummy)]
    impl AuthTokenUsingType<T> for AuthTokenType {
        type AuthToken = T;
    }
    #[derive(Error)]
    pub enum ValidateAuthTokenErr<Internal, Reason> {
        Invalid(#[from] Reason),
        Internal(Internal),
    }
    pub trait ValidateAuthToken: AuthTokenType {
        type InternalError;
        type InvalidReason;
        fn validate_auth_token(
            &self,
            auth_token: &Self::AuthToken,
        ) -> Result<(), ValidateAuthTokenErr<Self::InternalError, Self::InvalidReason>>;
    }

    pub trait FetchAuthTokenExpiry: AuthTokenType + TimeType {
        type Error;
        fn fetch_auth_token_expiry(
            &self,
            auth_token: &Self::AuthToken,
        ) -> Result<Self::Time, Self::Error>;
    }

    pub trait CurrentTime: TimeType {
        type Error;
        fn current_time() -> Result<Self::Time, Self::Error>;
    }
}

mod impls {
    use super::traits::*;
    use abstract_impl::abstract_impl;
    use datetime::LocalDateTime;
    use thiserror::Error;

    #[derive(Error)]
    pub enum ValidateTokenNotExpiredErr<CurrentTimeErr, FetchAuthTokenExpiryErr> {
        CurrentTime(CurrentTimeErr),
        FetchAuthTokenExpiry(FetchAuthTokenExpiryErr),
    }
    #[derive(Debug)]
    pub struct TokenExpired;
    #[abstract_impl(no_dummy)]
    impl ValidateTokenNotExpired for ValidateAuthToken
    where
        Self: CurrentTime + FetchAuthTokenExpiry,
        <Self as TimeType>::Time: Ord,
    {
        type InternalError = ValidateTokenNotExpiredErr<
            <Self as CurrentTime>::Error,
            <Self as FetchAuthTokenExpiry>::Error,
        >;
        type InvalidReason = TokenExpired;
        fn validate_auth_token(
            &self,
            auth_token: &Self::AuthToken,
        ) -> Result<(), ValidateAuthTokenErr<Self::InternalError, Self::InvalidReason>> {
            let now = Self::current_time()
                .map_err(Self::InternalError::CurrentTime)
                .map_err(ValidateAuthTokenErr::Internal)?;

            let token_expiry = self
                .fetch_auth_token_expiry(auth_token)
                .map_err(Self::InternalError::FetchAuthTokenExpiry)
                .map_err(ValidateAuthTokenErr::Internal)?;

            if token_expiry > now {
                Ok(())
            } else {
                Err(ValidateAuthTokenErr::Invalid(TokenExpired))
            }
        }
    }

    #[abstract_impl]
    impl TimeUsingLocal for TimeType {
        type Time = LocalDateTime;
    }
    pub enum Void {}
    #[abstract_impl(no_dummy)]
    impl UseLocalDateTime for CurrentTime
    where
        Self: TimeType<Time = LocalDateTime>,
    {
        type Error = Void;
        fn current_time() -> Result<LocalDateTime, Void> {
            Ok(LocalDateTime::now())
        }
    }
}

use datetime::LocalDateTime;
use impls::*;
use std::collections::BTreeMap;
use traits::*;

pub struct MockApp {
    pub auth_tokens_store: BTreeMap<String, LocalDateTime>,
}

impl_UseLocalDateTime!(MockApp);
impl_TimeUsingLocal!(MockApp);
impl_AuthTokenUsingType!(<String> MockApp);
impl_ValidateTokenNotExpired!(MockApp);

pub struct MissingToken;
impl FetchAuthTokenExpiry for MockApp {
    type Error = MissingToken;
    fn fetch_auth_token_expiry(
        &self,
        auth_token: &Self::AuthToken,
    ) -> Result<Self::Time, Self::Error> {
        self.auth_tokens_store
            .get(auth_token)
            .cloned()
            .ok_or(MissingToken)
    }
}

fn main() {
    let app = MockApp {
        auth_tokens_store: BTreeMap::from([(
            "Test".to_string(),
            LocalDateTime::now().add_seconds(10),
        )]),
    };
    let token = "Test".to_string();

    let _ = match app.validate_auth_token(&token) {
        Ok(res) => res,
        Err(ValidateAuthTokenErr::Invalid(reason)) => panic!("Token is invalid: {reason:?}"),
        Err(ValidateAuthTokenErr::Internal(ValidateTokenNotExpiredErr::FetchAuthTokenExpiry(
            MissingToken,
        ))) => panic!("Token {token} not found"),
    };
}
