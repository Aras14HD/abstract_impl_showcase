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

    #[derive(Error, Debug)]
    pub enum SiteError<Internal> {
        NotFound,
        Internal(#[from] Internal),
    }
    pub trait GetSite {
        type Site;
        type InternalErr;
        fn get_site<'a>(
            &'a self,
            uri: &str,
        ) -> Result<&'a Self::Site, SiteError<Self::InternalErr>>;
    }

    pub trait HasAuth {
        type Token;
        fn has_auth(&self, token: &Self::Token) -> bool;
    }

    pub trait Get<T> {
        fn get(self) -> T;
        fn get_ref(&self) -> &T;
        fn get_mut(&mut self) -> &mut T;
    }
    #[macro_export]
    macro_rules! impl_get_with_field {
        (<$t:ty> $s:ty {$e:ident}) => {
            impl Get<$t> for $s {
                fn get(self) -> $t {
                    self.$e
                }
                fn get_ref(&self) -> &$t {
                    &self.$e
                }
                fn get_mut(&mut self) -> &mut $t {
                    &mut self.$e
                }
            }
        };
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
    pub type Void = std::convert::Infallible;
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

    #[derive(Error, Debug)]
    pub enum SiteAuthError<Internal> {
        Forbidden,
        Internal(#[from] Internal),
    }
    #[abstract_impl]
    impl GetSiteWithAuth<SiteStore, S> for GetSite
    where
        SiteStore: GetSite + 'static,
        <SiteStore as GetSite>::Site: Get<S> + HasAuth,
        Self: Get<SiteStore> + Get<<<SiteStore as GetSite>::Site as HasAuth>::Token>,
    {
        type Site = S;
        type InternalErr = SiteAuthError<<SiteStore as GetSite>::InternalErr>;
        fn get_site<'a>(
            &'a self,
            uri: &str,
        ) -> Result<&'a Self::Site, SiteError<Self::InternalErr>> {
            let site = Get::<SiteStore>::get_ref(self)
                .get_site(uri)
                .map_err(|e| match e {
                    SiteError::Internal(i) => SiteError::Internal(SiteAuthError::from(i)),
                    SiteError::NotFound => SiteError::NotFound,
                })?;
            if !site.has_auth(self.get_ref()) {
                return Err(SiteError::Internal(SiteAuthError::Forbidden));
            };
            Ok(site.get_ref())
        }
    }
}

use datetime::LocalDateTime;
use impls::*;
use std::{collections::BTreeMap, time::Duration};
use traits::*;

type Token = String;
pub struct MockApp {
    pub auth_tokens_store: BTreeMap<Token, LocalDateTime>,
    pub sites: Sites,
    pub current_auth: Token,
}
impl_get_with_field!(<Token> MockApp {current_auth});
pub struct Sites(BTreeMap<String, Site>);
impl_get_with_field!(<Sites> MockApp {sites});
impl GetSite for Sites {
    type Site = Site;
    type InternalErr = std::convert::Infallible;
    fn get_site<'a>(&'a self, uri: &str) -> Result<&'a Self::Site, SiteError<Self::InternalErr>> {
        self.0.get(uri).ok_or(SiteError::NotFound)
    }
}
pub struct Site {
    pub content: String,
    pub privilege: Privilege,
}
impl_get_with_field!(<String> Site {content});
impl HasAuth for Site {
    type Token = Token;
    fn has_auth(&self, token: &Self::Token) -> bool {
        match &self.privilege {
            Privilege::None => true,
            Privilege::Whitelist(l) => l.contains(token),
            Privilege::Blacklist(l) => !l.contains(token) && token != "",
        }
    }
}
pub enum Privilege {
    None,
    Whitelist(Vec<Token>),
    Blacklist(Vec<Token>),
}

impl_GetSiteWithAuth!(<Sites, String> MockApp);
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
    let mut app = MockApp {
        auth_tokens_store: BTreeMap::from([
            ("Test".to_string(), LocalDateTime::now().add_seconds(1)),
            ("Other".to_string(), LocalDateTime::now().add_seconds(1000)),
        ]),
        sites: Sites(BTreeMap::from([
            (
                "/".to_string(),
                Site {
                    content: "Hi! This is our Site".to_string(),
                    privilege: Privilege::None,
                },
            ),
            (
                "/priv".to_string(),
                Site {
                    content: "This is private data!".to_string(),
                    privilege: Privilege::Whitelist(vec!["Test".to_string()]),
                },
            ),
            (
                "/not-him".to_string(),
                Site {
                    content: "This is semi private data!".to_string(),
                    privilege: Privilege::Blacklist(vec!["Test".to_string()]),
                },
            ),
        ])),
        current_auth: "".to_string(),
    };
    let token = "Other".to_string();

    // std::thread::sleep(Duration::from_secs(1));

    match app.validate_auth_token(&token) {
        Ok(_) => {
            app.current_auth = token;
        }
        Err(ValidateAuthTokenErr::Invalid(reason)) => eprintln!("Token is invalid: {reason:?}"),
        Err(ValidateAuthTokenErr::Internal(ValidateTokenNotExpiredErr::FetchAuthTokenExpiry(
            MissingToken,
        ))) => eprintln!("Token {token} not found"),
    };
    let site = app.get_site("/not-him").unwrap();
    println!("{site}");
}
